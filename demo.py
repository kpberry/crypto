from crypto import Communicator

alice = Communicator()
bob = Communicator()

alice.send_message('hello world!', bob)
alice.send_message('hellp world!', bob)
