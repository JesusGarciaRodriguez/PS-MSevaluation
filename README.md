# PS-MSevaluation
Implementation and evaluation of the PS-MS scheme (distributed p-ABCs based on multi-signatures, introduced in [1]). The code for comparing the execution times with the corresponding methods of the Idemix library is also included. The repository is divided into three folders:

## JavaPsBenchmark
The Java (Maven) project which contains the implementation and code for testing and evaluation.

## JARexecutions
Includes batch files and the JARS (with necessary libraries) generated using the project for "automated" experimentation.

## StatisticalStudy
Includes the Markdown script used to analyse the data obtained through the JAR executions.


[1] Jan Camenisch et al. Short Threshold Dynamic Group Signatures. Cryptology ePrint Archive, Report 2020/016. https://eprint.iacr.org/2020/016. 2020.