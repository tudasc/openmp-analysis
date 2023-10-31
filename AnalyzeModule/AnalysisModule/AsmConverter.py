import os
import sys
import shutil
from binaryornot.check import is_binary

def checkLocation(src, dest, ignore_endings, ignore_folders):
        result = False
        for file in os.listdir(src):
            tmppath = src + '/' + file
            if os.path.isdir(tmppath):
                ignore = False
                if(file in ignore_folders):
                    ignore = True
                if(not ignore):
                    newsrc = tmppath + '/'
                    newdest = dest + '/' + file + '/'
                    if not os.path.exists(newdest):
                        os.mkdir(newdest)
                    found = checkLocation(newsrc, newdest, ignore_endings, ignore_folders)
                    if found:
                        result = True
                    else:
                        shutil.rmtree(newdest)
            elif is_binary(tmppath):
                ignore = False
                ending = tmppath.split('.')[len(tmppath.split('.'))-1]
                if(ending in ignore_endings):
                    ignore = True

                if(not ignore):
                    source = tmppath
                    destination = dest + '/' + file
                    os.system('objdump -d "' + source + '" 2> error_file > "' + destination + '.asm"')
                    result = True
        return result

class AsmConverter:
    __slots__ = ()

    def __init__(self):
        pass

    # perform the analyses
    def __call__(self, source, destination, ignore_endings, ignore_folders, keep_data=False):
        result = checkLocation(source, destination, ignore_endings, ignore_folders)

        if(not result):
            print('Could not find any binaries in: ' + source)
            print('Keeping raw data due to this conflict.')
            shutil.rmtree(destination)
        #elif(not keep_data):
        #    shutil.rmtree(source)

        return result