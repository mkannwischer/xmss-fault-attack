
# 256 bit
# producing 10000 samples
for (( i=0; i<=10000; i++))
do
  
  for (( c=1; c<=40; c++ ))
  do
    file="data_new/P_1/N_32/$(c).log"
    ./attack2 32 8 4 1 $c --silent >> $file
  done
done
