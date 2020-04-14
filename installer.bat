@ECHO OFF
color 0a 
ECHO Make sure you are running Python 3.7 on a Windows machine.
ECHO INSTALLING THE REQUIRED MODULES...
ECHO 1/5
pip install wolframalpha api
ECHO 2/5
pip install pyttsx3
ECHO 3/5
pip install regex
ECHO 4/5
pip install requests
ECHO 5/5


echo Finished, starting redline.
python "Redline.py"