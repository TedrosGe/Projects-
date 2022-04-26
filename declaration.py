
def certifiedMailDeclaration():
    
    declaration = b"""
[Denotation]:
The symbols Ka1, Ka2, ..., Ka2n; Kb1, Kb2, ..., Kb2n
denote the solutions of the corresponding S puzzles:
Ca1, Ca2, ..., Ca2n; Cb1, Cb2, ..., Cb2n. The symbol
Ka0 denotes a key to F (Ka0 must satisfy (2) below).

[Statement]:
I acknowledge having received the mail, which results
from decrypting C by F using the key Ka0, if A can
present the following (i.e., both (1) and (2)):
(1) Both Kbi and Kb(n+i) for some 1 <= i <= n.
(2) Kaj, for all 1 <= j <= 2n, so that for every i,
    1 <= i <= n, Ka0 = Kai (+) Ka(n+i).
"""
                    
    return declaration