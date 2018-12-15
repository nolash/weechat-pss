# PSS plugin for Weechat

This script lets you send and receive messages through a `swarm` node using `pss`. If none of these terms mean anything to you, you have some research to do before reading on. See the references at the end of this README.

Ultimately, the idea is to create a proper shared object plugin which handles encryption internally and uses swarm nodes as multiplexers. 

However there is **lots** to be explored before that. And for this exploration we will use this simple prototype where you remote control a _single_ swarm node, using its public key and address.

## Version

0.1.11 alpha

## Development

If you want to help debugging this project I would greatly appreciate it. **You can help merely by trying to use it. No need to read code etc**

Please let me know if you do:

* email: dev@holbrook.no
* XMPP: lash@jabber.in-berlin.de
* gitter: @nolash
* status: lash.stateofus.eth 

My PSS node is:

* publickey: 0x04578fcba26eb70ff2cef4a1ee6de5bbcac169adc6a067be6dab2e1781234d8ba9e97782ee2e460589e2925762c602d97d463549d4314e104a1d67d283e103c427
* addr: 0xacae369e3fcef13ec171298c5d9a4ea3631cb4f082d9a72f8f95f27d54b4f145

#### Feedback

Let's use [issues on this repo](https://github.com/nolash/weechat-tools/issues) to inform us about trials and errors.

Please add an issue **both** if you successfully run the plugin and/or if something goes wrong.

The issue should contain the following:

* One of two title prefixes:
    - **PSS BUG** if it's a bug
    - **PSS USE** if it's a usage report
* Your version of the dependencies below (this will help identify minimum requirements).
* Consise description of what you've observed, and what you expected to observe.

## Dependencies

* [linux v4.19.8](http://kernel.org)
* [weechat v2.3](http://weechat.org) 
* [python v2.7.15](https://python.org)
* [python-websocket-client v0.54.0](https://pypi.org/project/websocket-client)
* [xmpppy v1.4.0](http://xmpppy.sf.net) (not used yet)

(Dependencies describe development environment, not minimal requirements)

## Installation

* Install [weechat](https://weechat.org) if you don't have it already.
* Change directory to `scripts/python` in this source tree.
* Copy the file `pss-single.py` and the `pss` directory along with its contents to the `python` subfolder in your weechat directory (normally this is `~/.weechat/python`)
* Start weechat
* Load the script with `/script load pss-single.py`

This adds a command `/pss` to your weechat instance. You can confirm load with calling the help text with `/help pss`


## Current features

* Connect to node
* Add recipients to node's address book
* Send message to recipient
* Receive messages received by node while connected to it
* Added recipients persist across sessions

(if you send a message and there is noone listening on the other node, they won't get the message later on. This is regardless of whether the node even is up or not.)

## Usage

You need a running instance of swarm to connect to. When you run swarm, remember to include the websockets flags, for example:

```
--ws --wsorigins="*" --wsport 8546
```

When swarm is running, you can continue.


```
# Connect to a pss node
# this will create a buffer with a node context
# if you don't supply host and port it uses defaults of 127.0.0.1 8546
/pss connect foo 127.0.0.1 8546

# While in the context of node you can issue commands to it
# (ctrl-x changes context, see weechat docs if you don't understand)
# Print public key of node
/pss key

# Print address of node
/pss address

# Add a peer to the node's address book
# After this you can send to the peer, and also incoming msgs matching the key will be marked by the nick you choose
# the key and address below is for _my_ node. If you want to add a different node, you need _that_ node's values.
/pss add lash 0x04578fcba26eb70ff2cef4a1ee6de5bbcac169adc6a067be6dab2e1781234d8ba9e97782ee2e460589e2925762c602d97d463549d4314e104a1d67d283e103c427 0xacae369e3fcef13ec171298c5d9a4ea3631cb4f082d9a72f8f95f27d54b4f145

# Send a message to the peer
# a new buffer will be created with name pss:<nick> (but won't focus automatically)
/pss msg lash the future is now

# you can also send from the node's buffer 
# in this case simply prefix the message with the nick
/buffer lash
I said, the future is now

# You can add other nodes to the same weechat instance
# Then you'll probably need different host and/or port other than the one already used
# You will be automatically switched to this node buffer
/pss connect bar 127.0.0.2 8547

# And of course you can even send between these nodes 
/pss key
[bar.key] 0xdeadbeef....feca1666
/pss address
[bar.address] 0xdeadbeef....feca1666
/pss add hsal <bar.key> <bar.address>
/pss msg hsal mais plus ça change, plus c'est la même chose

# if you close the other buffer
# it will re-open upon receiving a new message
/close lash
/buffer hsal
if you pardon my french...

# stop means disconnect. you can reconnect again and continue as before
/pss stop
/pss connect

# you can also issue commands from the core buffer, by prefixing the pss node name to the args
/buffer weechat
/pss bar msg lash cheer up, dude

# Unloading the script will kill sub-processes and disconnect from nodes
# Currently it will also erase all settings and nicks you've added
# It also removes the buffer and all messages in it are lost. Any logging of message is purely by accident.
/script unload pss

```

## Security

Although `pss` uses safe components for encryption, it is still not weather-tested in any way. Furthermore, this script adds code and traffic beyond the pss node, and at this point in time there's no guaranteeing that that won't break some security premise `pss` may already provide.

Most likely something in weechat are even logging the messages you're getting in cleartext, for example.

One thing to keep in mind is that anyone with access to your websocket port can connect to decrypt and see messages you receive.

If you're connecting to a node that's not on your local host but still want to keep the websocket port only available locally on the remote host, you can tunnel to the remote host and connect via localhost there:

`ssh -L 8546:localhost:8546 remote.ssh.host`

You can now reach that remote socket securely through your localhost 8546

## License

GPLv3

## References

* swarm - http://swarm-guide.readthedocs.com

## Changelog

* v0.1.11:
    - Reinstate node buffer, merge with core buffer
    - Make command context depend on buffer
    - Improve data validation tools
    - Remove conceal of setPeerPublicKey RPC return value
* v0.1.10:
    - Buffers now per recipient, not per node
    - Clean close of ws file descriptors
* v0.1.9:
    - Move rpc and pss/swarm specific components to pss package
* v0.1.8:
    - Move ws fd handling to newly discovered weechat hook_fd
    - Remind self to RTFM in the future before rushing to ipc acrobatics
* v0.1.7:
    - Handle by subprocess with FIFO pair
    - Add generic output formatting function for buffer
    - Add comments and make code nicer to look at
* v0.1.6:
    - Add connection reporting to frontend
    - Partial input processor on fifo
* v0.1.5:
    - Bugfix wrong recipient data added on connect
* v0.1.4:
    - Add sends from node buffer window
    - A touch of color
* v0.1.3:
    - Added persistent receipient store
    - Temporary solution with single append file
* v0.1.2:
    - Add README documentation
* v0.1.1:
    - Add message retrieval script run as background process
* v0.1.0:
    - Initial framework
