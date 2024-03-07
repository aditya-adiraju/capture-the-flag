from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time
import pause
from selenium.webdriver.remote.webelement import WebElement
from subprocess import Popen, PIPE, STDOUT
import functools
import subprocess
from selenium.webdriver import Firefox

# Return the timestamps to enter commands from the rust program
def get_timestamps() -> list[int]: 
    output = []
    with Popen(["cargo run", "src/main.rs"], shell=True, stdout=PIPE, stderr=STDOUT, text=True) as proc:
        for line in proc.stdout:
            output.append(line) 

    result = []
    for i in range(2, len(output), 2):
        print(output[i].split())
        result.append(int(output[i].split()[-1]))

    print("\n".join(output))

    return result

        
def main():
    # Create new instance of the webdriver with cookies? (it never worked iirc)
    subprocess_Popen = subprocess.Popen
    subprocess.Popen = functools.partial(subprocess_Popen, process_group=0)
    driver = Firefox()
    subprocess.Popen = subprocess_Popen  
    
    # Go to the chat link
    driver.get("https://osu.ppy.sh/community/chat?channel_id=55107714")

    # Give the user 30 seconds to deal with the 2FA on Osu!
    print("GOING TO SLEEP ZZZZZ")
    time.sleep(30)
    print("AWAKE AGAIN")

    # Find the text area element by its name attribute
    text_areas = driver.find_elements(By.TAG_NAME, "textarea")
    text_area = text_areas[0]

    # Time inputs for the rolls
    def try_solve():
        timestamps = get_timestamps()
        print([time.ctime(t) for t in timestamps])
        for i, ts in enumerate(timestamps):
            pause.until(ts)
            print(time.time())
            if i == 0:
                text_area.send_keys("!start")
            else:
                text_area.send_keys("!roll")

            text_area.send_keys(Keys.ENTER)
            print(time.time())

    try:
        try_solve()
    ## A janky way to rerun the rust program and start over.
    except KeyboardInterrupt:
        print("NEW instance")
        try_solve()

