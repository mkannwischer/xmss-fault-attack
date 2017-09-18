# Fault Attack on the XMSS^MT signature scheme
We propose and implement a fault injection attack on the multi-tree variant of XMSS (https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/).

A detailed description is available in my master thesis, which will be published shortly.


## License
Code delivered in this package by Matthias Julius Kannwischer is published under BSD (2-clause) license. Actual information about the specific license is to be found in each source code file.
We build upon the XMSS libof Stefan-Lukas Gazdag and Denis Butin (http://www.square-up.org/downloads/xmss_2016-07-26.tar.gz).

## Simulating the attack
- `make` should build the project including the XMSS library
- The attack simulation can then be used by running `./attack n h d p`, e.g., `./attack 32 10 2 1`
- The parameters are
  - `n`: security parameter (32 for 256 bits, 64 for 512 bits)
  - `h`: total height of the hyper tree
  - `d`: number of tree layers
  - `p`: number of forgery trails per iteration (see thesis for this parameter)
  - Not all combinations of h and d are possible (h must be divisible by d; see Internet Draft for full list of allowed combinations)
  - The implementation also supports other values for h than allowed in the Internet Draft
  - The `--silent` option disables all console logs except the results

## Performing Experiments
- [`./experiment_1.sh`](experiment_1.sh) will produce the data for Figure 6.3 (approx. runtime 2 days single-threaded)
- [`./experiment_2.sh`](experiment_2.sh) will produce the data for Figure 6.4 (approx. runtime 5 days single-threaded)
- [`./experiment_3.sh`](experiment_3.sh) will produce the data for Figure 6.5 (approx. runtime 7 days single-threaded)
- Note: The actual experiments have been conducted slighlty different, since we used multiple threads and machines. 

## Reproducing Plots
 - The data obtained from our experiments is included in this repository
 - The python script [`plots/create_plots.py`](plots/create_plots.py) can be used to reproduce the plots in the thesis
 - It depends upon http://www.numpy.org/ which needs to be installed

## Using the Code
 - Feel free to use, modify, and redistribute the code (according to the license)
 - [`xmss/`](xmss/) contains the XMSS library by Stefan-Lukas Gazdag and Denis Butin (http://www.square-up.org/downloads/xmss_2016-07-26.tar.gz)
   - We added a parameter `faulty` to `xmss_mt_sign` in [`xmssmt_draft.h`](xmss/xmssmt_draft.h) and [`xmssmt_draft.c`](xmss/xmssmt_draft.c) which allows the creation of faulty signatures
   - The rest is as published by Gazdag and Butin
 - [`data/`](data/) is used to hold the experiment results
 - [`plots/`](plots/) contains the script to reproduce the thesis plots
 - [`attack.c`](attack.c) entry point of the attack containing the majority of the attack
 - [`helper.c`](helper.c) procedures that help with the handling of chain values
 - [`recover_wots_pk.c`](recover_wots_pk.c) contains code that helps to recover a W-OTS+ public key from a valid XMSS^MT signature
 - [`forge_xmssmt_signature.c`](forge_xmssmt_signature.c) contains all code that is required to create a XMSS^MT forgery using a recovered partial W-OTS+ secret key
