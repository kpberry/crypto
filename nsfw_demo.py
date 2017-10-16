from crypto import Communicator

alice = Communicator()
bob = Communicator()

# NSFW
with open('dick_pic.html', 'r') as file:
    dick_pic = ''.join(line for line in file)

bob.send_message(dick_pic, alice)
