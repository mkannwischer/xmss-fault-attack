
# 256 bit
# producing 10000 samples
for (( i=0; i<=10000; i++))
do
  

  for k in 20 30 40 50;
  do
    for p in 2 4 8 16 32 64;
    do
      file="data_new/P_N1/N_32/k_"$k"_p_"$p".log"
      ./attack2 32 10 5 $p $k --silent >> $file
    done
  done
done
