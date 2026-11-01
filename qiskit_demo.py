"""Qiskit threat demos on the local Aer simulator (no IBM account, no real hardware).

Shor (toy N=15): shows WHY RSA / elliptic-curve style math is quantum-vulnerable.
Grover (3 qubits): shows the quadratic speed-up that leaves AES-256 safe.
These are textbook-size circuits. They do not attack any key used by QuantumShield.
"""
from __future__ import annotations

import math
from fractions import Fraction

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

# Multipliers a (coprime to 15) with a simple permutation circuit for y -> a*y mod 15.
SHOR_BASES = (2, 4, 7, 8, 11, 13)
N = 15


def _mult_mod15(a: int, power: int) -> QuantumCircuit:
    """Gate for y -> a^power * y (mod 15) on 4 qubits (little-endian)."""
    u = QuantumCircuit(4)
    for _ in range(power):
        if a in (2, 13):
            u.swap(2, 3); u.swap(1, 2); u.swap(0, 1)
        if a in (7, 8):
            u.swap(0, 1); u.swap(1, 2); u.swap(2, 3)
        if a in (4, 11):
            u.swap(1, 3); u.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                u.x(q)
    return u


def _inverse_qft(qc: QuantumCircuit, n: int) -> None:
    """Inverse QFT on qubits 0..n-1 (written out to be independent of Qiskit versions)."""
    for i in range(n // 2):
        qc.swap(i, n - 1 - i)
    for j in range(n):
        for m in range(j):
            qc.cp(-math.pi / 2 ** (j - m), m, j)
        qc.h(j)


def shor_circuit(a: int, n_count: int = 8) -> QuantumCircuit:
    """Order-finding circuit: n_count counting qubits + 4 work qubits holding y mod 15."""
    if a not in SHOR_BASES:
        raise ValueError(f"a must be one of {SHOR_BASES}")
    qc = QuantumCircuit(n_count + 4, n_count)
    for q in range(n_count):
        qc.h(q)
    qc.x(n_count)  # work register starts in |1>
    for q in range(n_count):
        gate = _mult_mod15(a, 2**q).to_gate(label=f"{a}^{2**q} mod 15").control(1)
        qc.append(gate, [q] + list(range(n_count, n_count + 4)))
    _inverse_qft(qc, n_count)
    qc.measure(range(n_count), range(n_count))
    return qc


def run_shor(a: int = 7, n_count: int = 8, shots: int = 1024, seed: int | None = None) -> dict:
    """Runs the circuit on Aer and classically post-processes the measured phases."""
    qc = shor_circuit(a, n_count)
    sim = AerSimulator(seed_simulator=seed)
    counts = sim.run(transpile(qc, sim), shots=shots).result().get_counts()
    rows = []
    for bits, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        meas = int(bits, 2)
        phase = meas / 2**n_count
        r = Fraction(phase).limit_denominator(N).denominator if phase else 1
        rows.append({"measured": meas, "phase": phase, "count": c, "guess_r": r})
    # Pick the most frequent guess r that is a valid order: a^r = 1 (mod 15)
    order, factors = None, None
    for row in rows:
        r = row["guess_r"]
        if r > 1 and pow(a, r, N) == 1 and r % 2 == 0:
            f1, f2 = math.gcd(pow(a, r // 2) - 1, N), math.gcd(pow(a, r // 2) + 1, N)
            if {f1, f2} == {3, 5}:
                order, factors = r, tuple(sorted((f1, f2)))
                break
    return {
        "a": a, "N": N, "counts": counts, "rows": rows, "order": order, "factors": factors,
        "qubits": qc.num_qubits, "depth": transpile(qc, sim).depth(), "shots": shots,
        "true_order": next(r for r in range(1, N) if pow(a, r, N) == 1),
    }


def run_grover(marked: int = 5, shots: int = 1024, seed: int | None = None) -> dict:
    """Grover search over 3 qubits (8 items). Optimal iterations for N=8 is 2."""
    if not 0 <= marked < 8:
        raise ValueError("marked must be in 0..7")
    bits = format(marked, "03b")[::-1]  # little-endian: bits[i] is qubit i

    def ccz(qc):
        qc.h(2); qc.ccx(0, 1, 2); qc.h(2)

    def results(iterations):
        qc = QuantumCircuit(3, 3)
        qc.h(range(3))
        for _ in range(iterations):
            for i, b in enumerate(bits):  # oracle: phase-flip |marked>
                if b == "0":
                    qc.x(i)
            ccz(qc)
            for i, b in enumerate(bits):
                if b == "0":
                    qc.x(i)
            qc.h(range(3)); qc.x(range(3)); ccz(qc); qc.x(range(3)); qc.h(range(3))  # diffuser
        qc.measure(range(3), range(3))
        sim = AerSimulator(seed_simulator=seed)
        counts = sim.run(transpile(qc, sim), shots=shots).result().get_counts()
        return {int(k, 2): v for k, v in counts.items()}

    out = {}
    for it in (0, 1, 2):
        c = results(it)
        out[it] = {"counts": c, "p_marked": c.get(marked, 0) / shots}
    return {"marked": marked, "shots": shots, "by_iterations": out}
