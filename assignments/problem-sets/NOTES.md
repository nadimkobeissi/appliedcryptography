# Ideas for later problem sets

```latex
\item (5 points) \textbf{TLS Under Attack:}
An advanced persistent threat (APT) group has compromised several Certificate Authorities and can issue valid certificates for any domain.
\begin{enumerate}
	\item Analyze exactly how this compromise allows attacks against TLS connections, even when users see the "secure" padlock icon.
	\item Design countermeasures that could be deployed by browser vendors to detect and prevent these attacks. Consider both technical and usability constraints.
	\item Evaluate certificate pinning as a solution: when does it work, when does it fail, and how should it be deployed?
	\item Compare your solutions to Certificate Transparency. What attacks does CT prevent, and what attacks does it miss?
\end{enumerate}

\item (5 points) \textbf{Signal's Double Ratchet Design Challenge:}
You're designing the next version of Signal's messaging protocol and want to improve upon the current Double Ratchet algorithm.
\begin{enumerate}
	\item Analyze the trade-off between security and performance in the current design: why does Signal perform a new DH exchange for each message direction rather than just once per conversation?
	\item Design an optimization that reduces the number of DH operations while maintaining the same security properties. What compromises would you accept?
	\item Consider a group messaging scenario with 100 participants. How would you adapt your design to provide forward secrecy and post-compromise security for group conversations?
\end{enumerate}

\item (5 points) \textbf{Quantum Timeline Decision Making:}
You're the CTO of a company building a secure messaging app expected to launch in 2028 and remain secure until 2040. Intelligence reports suggest large-scale quantum computers might exist by 2035, but with significant uncertainty (could be 2030 or 2045).
\begin{enumerate}
	\item Design a migration strategy that balances current performance needs with future quantum threats. What algorithms do you deploy now, and when do you plan upgrades?
	\item Analyze the "harvest now, decrypt later" threat: what data in your system needs protection beyond 2035, and how does this influence your cryptographic choices?
	\item Evaluate the trade-offs between early adoption of post-quantum cryptography (larger keys, unproven security) versus delayed migration (quantum vulnerability risk).
\end{enumerate}
```
