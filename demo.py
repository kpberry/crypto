from crypto import Communicator

alice = Communicator()
bob = Communicator()

alice.send_message('hello world!', bob)


# NSFW
with open('dick_pic.html', 'r') as file:
    dick_pic = '\n'.join(line for line in file)

bob.send_message(dick_pic, alice)