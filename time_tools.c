#include "time_tools.h"

// difference between 2 timevals in unsigned int (max 4290s)
unsigned int usec_diff(struct timeval x, struct timeval y){
        unsigned int diff;
        // if x is later than y
        if ((x.tv_sec > y.tv_sec)||(x.tv_usec > y.tv_usec)){
                diff = (1000000 * (x.tv_sec - y.tv_sec))
                        +(x.tv_usec - y.tv_usec);
                return diff;
        }
        // if y is later than x
        else if ((y.tv_sec >= x.tv_sec)||(y.tv_usec >= x.tv_usec)){
                diff = (1000000 * (y.tv_sec - x.tv_sec))
                        +(y.tv_usec - x.tv_usec);
                return diff;
        }
        // if fuckup?
        warn ("untimely error, fix it in the past?");
        return 666;
}

