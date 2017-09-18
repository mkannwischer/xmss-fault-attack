


# 512 bit
# producing 10000 samples
# approx. runtime (single-threaded): 5 days
for (( i=0; i<=100; i++))
do
  NOW=$(date +"%Y_%m_%d_%H_%M_%S")
  file="data/P_1/N_64/$(hostname)_$NOW.log"
  for (( c=1; c<=100; c++ ))
  do
    ./attack 64 8 4 1 --silent >> $file
  done
done
