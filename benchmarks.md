# Introduction

In this project, we embark on a journey to understand various Zero-knowledge proof systems with recursive capability, 
highlighting a consistent benchmark analysis of Poseidon across multiple circuits. 
While there are different computational layouts we could benchmark, we chose Poseidon due to its unique design, 
which offers fewer constraints in the circuit. This results in quicker proving times and possibly reduced proof sizes. 
In fact, Poseidon is explicitly tailored for optimal SNARK performance and has gained immense popularity in nearly every project that incorporates SNARKs. 
Thus, not only is it more efficiently optimized, but it also represents a common workload in SNARK-based systems. 
This makes our testing more representative of real-world scenarios and less theoretical.
We aim to meticulously evaluate Poseidon’s efficiency on zk-SNARK and zk-STARK circuit platforms like Nova, Arecibo, Halo2 Plonkish,  Halo2 SHPlonk, and Plonky2.
Through this comparison, we seek a holistic understanding of the advantages and drawbacks of each platform. 
Armed with this insight, we hope to determine the best framework tailored to our requirements.




# Considerations for Benchmarks

Evaluating various zero-knowledge proof systems is important, given the swift advancements in the field. 
When planning to benchmark these systems, we will try to adopt the following steps:

* First of all, we should select the parameters for evaluation. Commonly used metrics include: proof time, verifier time, proof size, and peak memory consumption.

* We should make sure that tests are being conducted under identical conditions, such as the hardware and the operating system.

* We should outline specific test scenarios for assessing each system, that can be influenced by varied input dimensions, 
various proof statements, and different security settings.

* We should also conduct several rounds of tests to factor in inconsistencies and derive a precise average.


A second step would be examining the results and looking beyond the performance. One should gather the data and scrutinize them in order to discern trends and observations. 
For instance, one system might offer quicker proof times but have extensive proof sizes, and another might be its inverse. 
Other factors should be considered besides the efficiency: the integration simplicity, the maturity of the proof system, and the assumptions about security and potential weak points. 
The ZKP community is always keen on benchmark data and comparisons, this is why we aim to publish our results through a blog and maybe if succeeded through an academic paper.

# The Four Proof Systems

We are interested in comparing four different proof systems: Nova, Arecibo, Halo2 Plonkish,  Halo2 SHPlonk, and Plonky2. In what follows, we will highlight the main differences between these systems.

* _Nova_: Nova presents a fresh methodology for incrementally verifiable computation (IVC) by introducing a folding mechanism, 
moving away from the traditional use of succinct non-interactive arguments of knowledge (SNARKs). 
Within IVC,the prover systematically demonstrates the accurate progression of incremental calculations represented as y = F (x).
A standout feature of Nova is its ability to boast the tiniest ”verifier circuit” documented in existing literature.
When utilizing the non-interactive variant of the folding method for relaxed R1CS (Rank-1 Constraint Systems), 
the verifier’s expenses remain consistent, leading to a verifier circuit of constant size, primarily influenced by two group scalar multiplications. 
The work required by the prover at each juncture is majorly defined by two multiexponentiations, roughly mirroring the magnitude of the incremental computation |F|.

   Nova’s methodology paves the way for executing IVC with a concise verifier circuit and streamlined prover calculations. 
 It sidesteps the need for FFTs and can be effectively set up using any elliptic curve cycles where the Discrete Logarithm Problem (DLOG) poses challenges.
 Furthermore, Nova integrates a proficient zero-knowledge succinct non-interactive argument (zkSNARK) to succinctly and confidentially validate the possession of legitimate IVC proofs. 
 This ensures a brief, confidential validation of a genuine IVC demonstration.
 
 * _Arecibo_: SuperNova protocol offers an efficient solution for virtual machine modelization and circuit operations, reducing costs and complexities. It innovates on Nova's folding 
 scheme by segmenting universal circuits into smaller sub-circuits, enhancing both complexity and cost efficiency. This effort aims to standardize the Non-Uniform Incremental Verifiable
 Computation (NIVC) approach, improving the folding scheme implementations significantly. The integration of the SuperNova protocol into Arecibo, is a significant leap in cryptographic 
 proofs and folding schemes. 
 
    Several optimizations were implemented to enhance the efficiency of the Arecibo implementation. Specifically, the number of variables and constraints in the recursive 
verification circuit were significantly reduced and the accuracy of the recursive SNARK verification was improved. This allows for the verification of the folding logic 
without the need to generate a full compressed SNARK.
  
    To avoid a malicious prover from generating a valid proof for any public input, Arecibo builds on the Bounded Witness Sumcheck which presents an effective solution
in both individual and batched settings, maintaining uniformity and enhancing security. Moreover, an optimized SNARK tailored for SuperNova's folded proofs was developed. 
Nova currently utilizes an adapted Spartan SNARK protocol for compressing relaxed R1CS instances at the final stage. With the advancement to SuperNova,  a batched version 
of the Spartan protocol was introduced. This version can verify several relaxed R1CS instances simultaneously within a single SNARK proof, significantly improving the efficiency of the verification process.
 
    To address the issue of the costs for both the prover and the verifier when compressing SuperNova proofs (which requires the prover to supply a distinct SNARK proof for every circuit), Arecibo implemented solution  that consolidates multiple Spartan proofs into a single batch for combined proof and verification. This innovative method substantially reduces the complexity for the verifier, equating it to the challenge of verifying a single Spartan proof, or two in the case of cycle of curves scenarios. This batching approach not only streamlines the verification process but also significantly cuts down on the resources and time required for both parties involved.
 
 

* _Halo2 (GWC)_: Halo2 emerges as a pioneering zk-SNARK framework, enabling recursive proof composition without a trusted setup, marking a significant advancement in cryptographic protocols. It operates based on the discrete log assumption, utilizing standard cycles of elliptic curves to verify complex computational tasks incrementally. A notable innovation within Halo2 is the introduction of a unique pair of elliptic curves, Tweedledum and Tweedledee, forming a 2-cycle that plays a critical role in its operations. 
 
   Incorporating UltraPLONK's advancements, Halo2 extends its capabilities with PLONKish circuits, which are designed with a focus on efficiency and flexibility. These circuits are organized in a matrix format, with components categorized into fixed, advice, and instance columns, supporting a variety of polynomial and lookup arguments. This structure is underpinned by a finite field \(F\), with configurations that include limits on constraint degrees and specific columns for equality constraints. 

   One of the keys to Halo2's efficiency is its utilization of specific endomorphisms, significantly reducing the size of the verification circuit. This ensures that both the proof size and the verification time remain manageable, regardless of the recursion levels involved. The protocol's design emphasizes minimizing resource requirements while maximizing performance, making it stand out in terms of proof size, recursion capability, and proving speed when compared to other zk-SNARK constructions. 

   By integrating PLONKish circuit designs, Halo2 leverages the strengths of UltraPLONK, including custom gates and enhanced lookup arguments, to support its innovative recursive proof system. This synergy between Halo2's foundational elliptic curve operations and the PLONKish circuit framework establishes a robust and efficient platform for secure, scalable, and trustless verification of computational tasks.

* _Halo2 (SHPlonk)_: SHPlonk is a significant advancement over the PLONK protocol, representing a more efficient solution compared to PLONK. Its implementation in Halo2 underscores its potential to build more scalable and secure blockchains.

   The key differentiator of SHPlonk lies in its utilization of a multi-poly commitment scheme, wherein the prover commits to multiple polynomials instead of just one. This approach adds an extra layer of security, as the verifier would need to guess the values of all committed polynomials to successfully refute the proof, thus reducing the likelihood of cheating. 
Furthermore, SHPlonk optimizes the polynomial commitment layer, offering advantages such as reducing the workload of the prover and enabling multiple polynomial openings. These benefits include a more effective commitment scheme compared to the KZG10 commitment, support for multi-polynomial and multi-openings, and a reduction in the number of elliptic curve operations required by the verifier. 

   By streamlining the verification process and reducing gas consumption, SHPlonk paves the way for the development of more efficient and scalable cryptographic protocols, making it a valuable tool for enhancing blockchain security and privacy.

* _Plonky2_: Plonky2 represents a cryptographic argument system designed for rapid recursive composition. While it’s grounded in the TurboPLONK arithmetization framework, 
it diverges by integrating the FRI (Fast Reed- Solomon Interactive Oracle Proof) into its polynomial testing approach. 
This integration enables Plonky2 to represent the witness using a 64-bit field, leading to enhanced prover efficiency.
A standout characteristic of Plonky2 is its proficiency in condensing extensive proofs down to a consistent size. 
Depending on specific security and latency needs, Plonky2 has the capability to reduce any proof to an approximate size of 43 kilobytes. 
This compression is realized through recursive techniques, facilitating the minimization of even the most extensive proofs.

     From a performance standpoint, Plonky2 is engineered for speed. A standard laptop can produce a recursive proof in roughly 300 milliseconds with Plonky2. 
This efficiency positions it as an ideal choice for real-world scenarios demanding swift proof creation.
In summary, Plonky2 brings to the table a swift recursive composition, augmented prover efficiency via a 64-bit field representation, 
and the prowess to consistently condense extensive proofs. These attributes underscore its significance in the realm of cryptographic argument implementations.

* _Starky_: Starky can be viewed as the STARK counterpart of Plonky2. While STARKs are a subset of the PLONK framework, Starky offers advantages over Plonky2. 
Plonky2 is specifically designed for recursion and heavily relies on custom gates. In contrast, Starky can be described as Plonky2 stripped of PLONK-specific elements.
One of Starky’s notable strengths is its speed. This is attributed to its transition constraints, where a constraint on degree 3 leads to a rate of 2. 

    On the other hand, Plonky2 imposes limitations on the degree of constraints, preventing them from being too low, typically at degree 5. 
A smaller rate translates to a faster proof, making Starky more efficient in this regard.

# Circuit Implementation

To achieve our goal, we would like to ensure a balanced comparison between the different proof systems, especially when benchmarking their performance. 
One effective method to achieve this is by writing circuits for each system. By employing a universally accepted operation, 
such as a hash function, we aim to guarantee that every system undergoes an evaluation based on an identical computational task. 
This not only ensures fairness but also provides clarity in understanding the nuances of each system. In what follows our structured guide:

* _Hash function selection_: One should opt for a universally acknowledged hash function, such as SHA-256, Poseidon, or Blake2s. 
It’s essential to ensure its compatibility or efficient representation across all proof systems.

* _Deciphering Arithmetization_: Since each proof system has its unique computational representation, one should delve into the arithmetization each employs, like R1CS for SNARKs or AIR for STARKs.

* _Crafting the Circuit_: To better implement circuits, one should check the official resources. For Nova, it is advisable to consult Microsoft’s Github page dedicated for Nova. 
Concerning Halo2, one could leverage the resources offered by the Electric Coin Company. Regarding Plonky2 and Starky, one should navigate into AIR and PLONK implementations.

* _Validation_: Prior to benchmarking, it’s crucial to ascertain the circuit’s functionality. Produce and authenticate proofs to guarantee accuracy.

* _Benchmarking_: One should record measurements such as the time taken for proof generation, the duration of validation, and the size of the proof for every system. 
Ensuring a uniform benchmarking environment is crucial to uphold the credibility of the results.

The goal is to maintain consistent functionality across all systems. Even though their structural designs may vary, the outcomes they produce should be uniform, guaranteeing a fair comparison.

# Hash Functions

When selecting a hash function for ZKP circuits, several factors come into play. The efficiency of some hash functions, 
is accentuated when they are represented as arithmetic circuits, a representation frequently used in many ZKP systems. 
It’s also essential to prioritize robust security by choosing a hash function that showcases cryptographic strength. 

Additionally, the adoption rate of certain hash functions within the ZKP community can be a telling sign, 
as some are more widely embraced, often due to their optimized circuit designs or specialized ”gadgets.” 

Lastly, the specific needs of your application might dictate the importance of the hash output’s size,
with considerations such as whether a 256-bit output suffices or a larger 512-bit output is more appropriate.
In what follows, a list of some hash functions that have emerged as popular choices, each with its unique attributes:

* _Pedersen Hashes_: Pedersen Hashes are recognized for their efficiency when represented in arithmetic circuits and are frequently employed in zk-SNARK applications. 
However, their cryptographic robustness might not be on par with some alternatives, making them more apt for niche applications.

* _MiMC_: MiMC is designed for peak performance in arithmetic circuits, particularly over finite fields, 
and has found its place in certain zk-SNARK applications.

* _Blake2s_: Blake2s is lauded for its cryptographic strength and swift performance, often outpacing the likes of SHA-256. 
A specific variant of Blake2s, optimized for 32-bit platforms, has demonstrated efficiency in ZKP scenarios, making it a preferred option for zk-STARKs.

* _SHA-256_: SHA-256, a globally recognized hash function, boasts a strong security framework. 
However, its complex representation might render it less efficient in some ZKP scenarios.

* _Poseidon_: Poseidon stands out as a hash function crafted explicitly with ZKPs in mind, focusing on achieving low multiplicative complexity.

### <ins> SHA-256 Vs. Poseidon </ins>

SHA-256 and Poseidon are cryptographic hash functions, each with distinct designs and purposes, especially within the zero-knowledge proof (ZKP) framework.

* **SHA-256**: SHA-256, part of the SHA-2 family, operates using the Merkle–Damg ̊ard construction, processing input in 512-bit blocks to yield a 256-bit hash output.
Its design is rooted in bitwise operations, including AND, OR, XOR, bit shifts, and rotations, combined with modular arithmetic. 
While SHA-256 is cryptographically robust and efficient on standard hardware, its bit-wise nature poses challenges in zk-SNARK circuits. 
Specifically, these operations can be resource-intensive when translated to the arithmetic circuits preferred by zk-SNARKs, 
leading to larger and more computationally demanding circuits.

* **Poseidon**: Poseidon, is architected with ZKPs in mind. It employs the sponge construction, a permutation-based design optimized for operations over finite fields. 
This focus on prime field arithmetic is a boon for zk-SNARKs, aligning seamlessly with their arithmetic circuit representations. 
Furthermore, Poseidon emphasizes fewer multiplication gates, which are typically ”costly” in zk-SNARK circuits. 
As a result, its design leads to circuits with fewer constraints, enabling faster proving times and potentially more compact proof sizes.


In the context of ZKPs, the distinction between SHA-256 and Poseidon is primarily their operational nature. SHA-256’s bitwise operations, 
while secure and efficient in traditional contexts, can be cumbersome in zk-SNARK circuits. Poseidon, with its prime field arithmetic, 
offers a more streamlined and efficient integration into zk-SNARK environments. In summary, for ZKP applications prioritizing efficiency and streamlined circuit design, 
Poseidon emerges as a technically apt choice, which justifies our selection of adopting Poseidon in our circuits.

# Recursion for Fair Comparison

Recursive proof composition in zero-knowledge proof systems offers a transformative approach to scalability and efficiency.
By enabling a proof system to generate a proof that attests to the validity of another proof, recursion allows for the aggregation of multiple proofs into a single, compact representation. 
This is especially beneficial in blockchain contexts, where it can keep the blockchain size constant regardless of transaction volume, leading to significant bandwidth and storage savings. 

Beyond scalability, recursive proofs enhance efficiency by allowing batch verification of multiple proofs in a single step, reducing computational overhead and speeding up transaction validations. 
This nested validation mechanism also bolsters privacy and security, as users can prove the validity of their actions without revealing the actions themselves. 
Some recursive zk-SNARK constructions, like Halo2, even eliminate the need for a trusted setup, reducing potential vulnerabilities. 

While the introduction of recursion brings added complexity in circuit design and cryptographic constructions, the scalability, 
efficiency, and privacy gains often justify its adoption. Moreover, despite the relative novelty of recursive zk-SNARK constructions, 
ongoing research, and successful implementations are steadily building confidence in their robustness and utility. 
When compared to alternative solutions, such as non-recursive zk-SNARKs or zk-STARKs with larger proof sizes, 
the benefits of recursion often stand out, especially in applications demanding high scalability and privacy.

When benchmarking cryptographic systems, ensuring a fair comparison is paramount. Here's why using Halo2 with recursion is a fair choice when comparing it to Nova:

* _Proof Aggregation_: Proof aggregation is a primary feature of recursive systems and is crucial for scalability. By comparing both systems with this feature, 
we're examining their ability to handle a large volume of proofs, which is the purpose of our project.

* _Compactness_: Recursive systems, by their nature, produce compact proofs regardless of the number of aggregated proofs. 
Comparing Halo2 with recursion to Nova ensures that we're evaluating the efficiency and compactness of proofs under similar conditions.

* _Batch Verification_: Recursive proofs allow for the batch verification of multiple proofs in a single step. By using Halo2 with recursion, 
we ensure that the verification process is consistent with that of Nova, allowing for a direct comparison of verification times and computational overhead.

* _Nested Validations_: Both systems would utilize nested validations, ensuring a layered security and privacy approach. 
This means we're comparing how each system achieves privacy and security using similar mechanisms.

* _Trusted Setup_: Some recursive zk-SNARK constructions, including Halo2, eliminate the need for a trusted setup. 
Since Nova also operates without a trusted setup, then comparing it to Halo2 with recursion ensures that we're evaluating both systems under similar trust assumptions.

* _Design and Cryptographic Challenges_: Recursive systems introduce added complexity in circuit design and cryptographic constructions. 
By comparing Halo2 with recursion to Nova, we're evaluating how each system handles and optimizes these complexities.

### <ins> Halo2: Lookup Tables Vs. Recursion  </ins>


| Feature/Aspect             | Recursive zk-SNARKs (e.g., Halo2 with Recursion) | Non-Recursive zk-SNARKs (e.g., Halo2 with Lookup Tables) | zk-STARKs |
|---------------------------|-------------------------------------------------|--------------------------------------------------------|----------|
| **Proof Size**            | Compact                                         | Larger compared to recursive proofs                    | Large    |
| **Scalability**           | High (due to proof aggregation)                  | Moderate                                               | Moderate |
| **Computational Efficiency** | Varies (depends on depth of recursion)       | Enhanced (due to lookup tables)                        | Varies   |
| **Privacy**               | High (nested validations)                       | High                                                   | High     |
| **Trusted Setup**         | Not required in some constructions (e.g., Halo2)| Typically required                                     | Not required |
| **Complexity**            | Increased (due to recursion)                    | Moderate (due to lookup tables)                        | Moderate |
| **Robustness & Maturity** | Growing with ongoing research                   | Established                                           | Established |


For our benchmarks to yield meaningful results, it's essential that the systems being compared are evaluated under similar conditions and objectives. 
Using Halo2 with recursion ensures that we're comparing it to Nova on a level playing field, focusing on their ability to achieve scalability, efficiency, 
privacy, and security using recursive proof composition. This approach ensures that the results are indicative of each system's performance and capabilities, 
in real-world scenarios where recursion is a primary requirement.
