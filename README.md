# detnetctl - A TSN/DetNet Node Controller with Interference Protection

The purpose of detnetctl is to coordinate different applications requiring real-time communication (in the sense of TSN or DetNet) running on the same Linux system.
The main focus is to avoid interference between different networking applications, even if they can not be fully trusted to be cooperative.
For example, this prevents the situation that two applications send with the same `SO_PRIORITY` due to misconfiguration, bugs or security issues
and thus might sent their traffic in the same time slot leading to missed deadlines.

In its current status, this software should be classified as demonstrator or research prototype intended for collecting experience with the requirements.
For feedback or if you have a related productive use case, please contact [Linutronix](https://linutronix.de/).

