# ARP Attack

## Lab Environment

The lab environment is composed of 3 machines. An attacker and 2 hosts. Each machine has her own docker container and all 3 containers should be running at the same time.

All the code is developed outside of the containers, in the 'volume' directory. This is a shared directory with the attacker's container, so all code developed there will appear in the attacker's container.

Address Table:
  - **Attacker:** 10.9.0.105
  - **Host A:** 10.9.0.5
  - **Host B:** 10.9.0.6


## Task 1

### Task 1.A


### Task 1.B

Scenario 1 : The reply packet attack successefully changes the mac adress on machine A ARP table.

Scenario 2 : In this particular case, machine A ignores the reply packet, thus leading to a failed attack attempt.

### Task 1.C
