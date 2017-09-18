# different values for p
# producing 1000 samples for each value of p
# approx. runtime (single-threaded): 7 days

# note: the actual data was obtained differently (different sample size for each value of p)

for i in 2 4 8 16 24 32;
do
  NOW=$(date +"%Y_%m_%d_%H_%M_%S")
  file="data/P_NOT1/P_$i/$(hostname)_$NOW.log"
  for (( c=1; c<=1000; c++ ))
  do
    ./attack 32 8 4 $i --silent >> $file
  done
done
