#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
 * Copyright (c) 2017, Matthias Julius Kannwischer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''

import csv
import math
import numpy as np
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

def parse_csv(i):
    ifile = open("../data_new/P_1/N_32/%d.log"%i, "rb")
    reader = csv.reader(ifile, delimiter=';')
    values = []
    for row in reader:
        values.append(int(row[10]))
    ifile.close()
    return values

def plot_lines(x, exp, theo, fname):
    f = plt.figure(figsize=(11,5))
    
    plt.ylim(ymin=-0.1)
    plt.ylim(ymax=1.1)
    plt.plot(x,theo,color="orange")
    plt.plot(x,exp,color="blue")
    plt.tight_layout()
    #plt.figtext(.1, .2, scatter_txt(x, y))
    #plt.show()
    f.savefig(fname)

def prob(W, ell,q):
    W = float(W)
    ell = float(ell)
    q = float(q)
    s = 0
    for x in range(0,int(W)):
       s += 1 - ((W-(x+1))/W)**(q+1)
    s = s**ell
    return s/(W**ell)



#print parse_csv()


# 1 means failure; 0 is success
data = map(lambda(l): (sum(l), len(l)), map(lambda (i): parse_csv(i), xrange(1,111)))
exp_results = map(lambda (fail, all): (float(all)-fail)/all, data)
theoretical_results = map(lambda(q): prob(16, 67, q), xrange(1,111))

plot_lines(range(1,111), exp_results, theoretical_results, "FA_new_N32.pdf")

