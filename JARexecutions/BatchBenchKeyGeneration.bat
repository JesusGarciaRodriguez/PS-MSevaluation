FOR /L %%A IN (2,1,10) DO java -Xbootclasspath/p:.\lib\amcl-3.2-SNAPSHOT.jar -jar BenchmarkKeyGeneration-jar-with-dependencies.jar %%A 1 10