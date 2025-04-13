import os # Imports the os module, which provides functions to interact with the operating system.
import subprocess #Imports the subprocess module, which allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.
import pyshark #Imports the pyshark module, which is used for packet analysis and reading Wireshark capture files.

def Open_cmd_prmpt(): # tThis function prompts the user to enter the path of the Wireshark file and returns the entered file path.
    # Open command prompt and ask for the path of the Wireshark file
    file_path = input("Please enter the path of the Wireshark file: ")
    return file_path #returning the file path to wireshark_path = Open_cmd_prmpt()

def apply_filter_and_get_data(wireshark_path): #This function executes by taking the wireshark file path as an argument.
    # Use pyshark to read the Wireshark file and apply the filter and will store in capture variable
    capture = pyshark.FileCapture(wireshark_path, display_filter='data.data[0:8]==04:ff:ff:01:09:00:02:f4')
    packets = [] #taking an empty list to store the packets
    for packet in capture: #looping the capture of wireshark data in the capture and putting each capture in the packet
        if 'data' in packet: #Taking each packet and checking does that packet has a data or it is normal packet which doesn't have payload data
            packets.append(packet.data.data) # appending that data.data into the list called packets
    capture.close() #closing the capture
    return packets # returning the packets to apply_filter_and_get_data function call


def checking_validity(packets): #function written to check the validity of each tag in the packet
    valid = True #initializing the variable valid to True
    first_print_done = False  # Flag to check if the first print statement has been executed
    with open("output.txt", "w") as f: #opening the text file in the same folder where the .exe file locates and using f as a parameter to write in to that
        for i, packet in enumerate(packets): #taking all the packets list and collecting each value in list one by one using enumerate and also we are putting the index for each packet starting from 0 and then giving actual single data to packet and giving the index to i
            data = packet #before going to further putting the packet's value in to data

            data = data[72:]  # Remove first 72 characters before entering in to the below loop

            while len(data) >= 10: #from here the loop starts and then it check the remainig data is more than 10 characters
                data = data[10:]  # Remove next 10 characters

                if len(data) < 8: #check if the remaining length is having less than 8 characters
                    break # if yes then it will break
                if data[:2] == '08': # check the next 2 characters are 08
                    data = data[4:]  # if yes, Remove 4 characters

                elif data[:2] == '0b': #if above fails it will check the next two characters are 0b
                    data = data[10:]  # if yes, Remove 10 characters
                    #print(f"After removing 10 characters: {data}", file=f)
                if len(data) < 2: #check the remaining data is less than 2
                    break #if yes break the loop
                if data[:2] != '03': #check the remaining data first two characters are not haiving 03
                    if not first_print_done: # if there is no data in the first_print_done variable which we initialized above at starting of the function
                        print("Below are the packets which are not having proper validity for tag(s).\n", file=f) #if yes it will write this value in to that variable
                        first_print_done = True #set first_print_done to True
                    print(f"S.NO: {i + 1}, Packet: {packet}", file=f) # Giving the S.NO by taking the index i (since it will start from 0 we are adding +1 to it) and then taking the data from packet and adding that to output.txt file using variable f
                    #print("This packet is not proper", file=f)
                    valid = False # making the valid as false
                    break
                # data = data[2:]# removing 03
                # Step e: Remove next 12 characters and continue from step b
                data = data[14:] #if above if loop     if data[:2] != '03':     didn't executed then this will get executed to remove the next 14 chracters in the data

        if valid: # Comes out of the above while loop and then check the variable valid is having True or false
            print("All the packets in the wireshark is having proper validity!!", file=f) #if it is True then only executes this print function to write this data in to that output.txt file using variable f


wireshark_path = Open_cmd_prmpt() #  Calls the Open_cmd_prmpt() function to get the Wireshark file path.
packets = apply_filter_and_get_data(wireshark_path) #Calls the apply_filter_and_get_data(wireshark_path) function to get the packet data.
checking_validity(packets) #Calls the checking_validity(packets) function to check the validity of the packets and write the results to output.txt.
