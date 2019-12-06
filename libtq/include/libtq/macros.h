#pragma once

#define TQ_PASTE_(a,b) a##b
#define TQ_PASTE(a,b) TQ_PASTE_(a,b)
#define TQ_PASTE3(a,b,c) TQ_PASTE(TQ_PASTE_(a,b),c)
#define TQ_PASTE4(a,b,c,d) TQ_PASTE(TQ_PASTE3(a,b,c),d)
