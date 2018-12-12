# pss-single.py

* version: 0.1.5 alpha

This script lets you send and receive messages through a `swarm` node using `pss`. If none of these terms mean anything to you, you have some research to do before reading on. See the references at the end of this README.

Ultimately, the idea is to create a proper shared object plugin which handles encryption internally and uses swarm nodes as multiplexers. 

However there is **lots** to be explored before that. And for this exploration we will use this simple prototype where you remote control a _single_ swarm node, using its public key and address.

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
* Copy the files `pss-single.py` and `pss-fetch.py` along with the `pss` directory along with its contents to the `python` subfolder in your weechat directory (normally this is `~/.weechat/python`)
* Start weechat
* Load the script with `/script load pss-single.py` (do _not_ load `pss-fetch.py`)

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
# Register a new pss instance in the plugin:
/pss new foo

# Connect to the node
# by default host 127.0.0.1 port 8546
# when connected a message buffer for that node is created
# the buffer will be named pss_<pssname>, in this example pss_foo
/pss foo connect

# Print public key of node
/pss foo key

# Print address of node
/pss foo address

# Add a peer to the node's address book
# After this you can send to the peer, and also incoming msgs matching the key will be marked by the nick you choose
# the key and address below is for _my_ node. If you want to add a different node, you need _that_ node's values.
/pss foo add lash 0x04578fcba26eb70ff2cef4a1ee6de5bbcac169adc6a067be6dab2e1781234d8ba9e97782ee2e460589e2925762c602d97d463549d4314e104a1d67d283e103c427 0xacae369e3fcef13ec171298c5d9a4ea3631cb4f082d9a72f8f95f27d54b4f145

# Send a message to the peer from the weechat buffer
/pss foo send lash the future is now

# you can also send from the node's buffer 
# in this case simply prefix the message with the nick
/buffer pss_foo
lash I said, the future is now

# You can add other nodes to the same weechat instance
# Then you'll probably need different host and/or port other than 
/buffer weechat
/pss new bar
/pss bar set host 127.0.0.2
/pss bar set port 8547
/pss bar connect

# And of course you can even send between these nodes 
/pss bar key
[bar.key] 0xdeadbeef....feca1666
/pss bar address
[bar.address] 0xdeadbeef....feca1666
/pss bar connect
/pss foo add hsal <bar.key> <bar.address>
/pss foo send hsal mais plus ça change, plus c'est la même chose

# or from the bar buffer
/buffer pss_bar
hsal ...if you pardon my french

# Unloading the script will kill sub-processes and disconnect from nodes
# Currently it will also erase all settings and nicks you've added
# It also removes the buffer and all messages in it are lost. Any logging of message is purely by accident.
/script unload pss

```

## Advanced

Upon connecting to a node, a subprocess loop will be started that receives incoming messages and passes it to the main process through a FIFO.

The subprocess catches disconnect exceptions from the websocket and retries forever.

If the FIFO can't be written to, the sub-process will quit after a number of retries. Whatever happens if the sub-process quits prematurely is currently undefined.

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

- v0.1.6: Add connection reporting to frontend + partial input processor on fifo
- v0.1.5: Bugfix wrong recipient data added on connect
- v0.1.4: Add sends from node buffer window + a touch of color
- v0.1.3: Added persistent receipient store, temporary solution with single append file
- v0.1.2: Add README documentation
- v0.1.1: Add message retrieval script run as background process
- v0.1.0: Initial framework
