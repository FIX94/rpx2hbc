# rpx2hbc
a wiiu homebrew version of hbl2hbc but for building wiiu channels to boot a specific vwii title  
essentially a stripped down version of this repo:  
https://github.com/dimok789/homebrew_launcher/tree/homebrew_launcher_rpx  
the vwii channel id it boots is at line 620 in sd_loader/src/entry.c so you can modify that and then just run "make" from the main directory  
this uses fairly old libs, only tested using devkitppc r27, some older libogc version for .h files and I used these particular libs of wut:  
https://mega.nz/#!9o5xQaAB!zW3WZ46PgP33EFoCtofiFzm41GX01slVS4zHLQ-jCQU  
thanks to morpheous for nagging me to actually write this up and testing as well as NexoCube for testing  