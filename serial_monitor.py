import serial
import time
import random
import sys

def main():
    # Configure serial port - can be overridden by command line arg
    port = '/dev/ttyUSB0'  # Default
    if len(sys.argv) > 1:
        port = sys.argv[1]

    baudrate = 9600

    try:
        ser = serial.Serial(port, baudrate, timeout=1)
        print(f"Connected to {port} at {baudrate} baud")
    except serial.SerialException as e:
        print(f"Error opening serial port: {e}")
        print("Make sure the device is connected and the port is correct.")
        return

    print("Serial Monitor for Button Press Timing")
    print("This script will tell you when to press the button and measure the detection time.")
    print("Make sure the ESP8266 is running and connected.")
    print(f"Using serial port: {port} at {baudrate} baud")
    print("Usage: python serial_monitor.py [port]  (default: /dev/ttyUSB0)")
    print()

    trials = 5  # Number of trials

    for trial in range(1, trials + 1):
        print(f"Trial {trial}/{trials}")

        # Wait for button to be released before starting
        print("Waiting for button to be released... (do not press the button yet)")
        received_data = ""
        while True:
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                received_data += data
                print(f"Serial: {data.strip()}")
                if "BUTTON RELEASED" in received_data:
                    print("Button is released. Starting trial.")
                    time.sleep(1)  # Extra delay to ensure stable
                    break
            time.sleep(0.1)

        # Wait for a random time between 2-5 seconds
        wait_time = random.uniform(2, 5)
        print(f"Get ready... Press the button in {wait_time:.1f} seconds")
        time.sleep(wait_time)

        start_time = time.time()
        print("PRESS THE BUTTON NOW!")

        # Clear any pending serial data
        ser.reset_input_buffer()

        # Wait for "BUTTON PRESSED" from serial with timeout
        timeout = 3.0  # seconds - reduced since user reaction is ~1-2s
        detected = False
        received_data = ""
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
                received_data += data
                print(f"Serial: {data.strip()}")  # Debug: print incoming data
                if "BUTTON PRESSED" in received_data:
                    end_time = time.time()
                    detection_time = (end_time - start_time) * 1000  # in ms
                    print(f"Button detected! Time to detect: {detection_time:.2f} ms")
                    detected = True
                    break
            time.sleep(0.01)  # Small delay to avoid busy waiting

        if not detected:
            print("Timeout: Button not detected within 3 seconds. Try pressing faster.")

        # Wait a bit before next trial
        time.sleep(2)

    ser.close()
    print("Done!")

if __name__ == "__main__":
    main()