


# 256 bit
# producing 10000 samples
# approx. runtime (single-threaded): 2 days
for (( i=0; i<=100; i++))
do
  NOW=$(date +"%Y_%m_%d_%H_%M_%S")
  file="data/P_1/N_32/$(hostname)_$NOW.log"
  for (( c=1; c<=100; c++ ))
  do
    ./attack 32 8 4 1 --silent >> $file
  done
done
