/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

/**
 * @fileoverview Remote procedure call library for gadget-to-container,
 * container-to-gadget, and gadget-to-gadget (thru container) communication.
 */
var gadgets = gadgets || {};

/**
 * Transports used by core gadgets.rpc code to actually pass messages.
 * each transport implements the same "interface" exposing hooks that
 * the core library calls at strategic points to set up and use
 * the transport. This isn't really an interface, of course, since
 * the code is JS and each transport is a singleton, but it's treated
 * as such by core code.
 *
 * The methods each transport must implement are:
 * + getCode(): returns a string identifying the transport. For debugging.
 * + isParentVerifiable(): indicates (via boolean) whether the method
 *     has the property that its relay URL verifies for certain the
 *     receiver's protocol://host:port.
 * + init(processFn, readyFn): Performs any global initialization needed. Called
 *     before any other gadgets.rpc methods are invoked. processFn is
 *     the function in gadgets.rpc used to process an rpc packet. readyFn is
 *     a function that must be called when the transport is ready to send
 *     and receive messages bidirectionally. Returns
 *     true if successful, false otherwise.
 * + setup(receiverId, token): Performs per-receiver initialization, if any.
 *     receiverId will be '..' for gadget-to-container. Returns true if
 *     successful, false otherwise.
 * + call(targetId, from, rpc): Invoked to send an actual
 *     message to the given targetId, with the given serviceName, from
 *     the sender identified by 'from'. Payload is an rpc packet. Returns
 *     true if successful, false otherwise.
 */
gadgets.transports = {};

/**
 * Transport for browsers that support native messaging (various implementations
 * of the HTML5 postMessage method). Officially defined at
 * http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html.
 *
 * postMessage is a native implementation of XDC. A page registers that
 * it would like to receive messages by listening the the "message" event
 * on the window (document in DPM) object. In turn, another page can
 * raise that event by calling window.postMessage (document.postMessage
 * in DPM) with a string representing the message and a string
 * indicating on which domain the receiving page must be to receive
 * the message. The target page will then have its "message" event raised
 * if the domain matches and can, in turn, check the origin of the message
 * and process the data contained within.
 *
 *   wpm: postMessage on the window object.
 *      - Internet Explorer 8+
 *      - Safari (latest nightlies as of 26/6/2008)
 *      - Firefox 3+
 *      - Opera 9+
 */
gadgets.transports.Wpm = function() {
  var ready;

  return {
    getCode: function() {
      return 'wpm';
    },

    isParentVerifiable: function() {
      return true;
    },

    init: function(processFn, readyFn) {
      ready = readyFn;
      // Set up native postMessage handler.
      window.addEventListener('message', function(packet) {
        // TODO validate packet.domain for security reasons
        processFn(gadgets.json.parse(packet.data));
      }, false);
      ready('..', true);  // Immediately ready to send to parent.
      return true;
    },

    setup: function(receiverId, token) {
      // If we're a gadget, send an ACK message to indicate to container
      // that we're ready to receive messages.
      if (receiverId === '..') {
        gadgets.rpc.call(receiverId, gadgets.rpc.ACK);
      }
      return true;
    },

    call: function(targetId, from, rpc) {
      var targetWin = targetId === '..' ? parent : frames[targetId];
      var relay = gadgets.rpc.getRelayUrl(targetId);
      if (relay) {
        targetWin.postMessage(gadgets.json.stringify(rpc), relay);
      }
      return true;
    }
  };
}();

/**
 * Similar transport to WPM, but uses document element instead.
 * This was implemented by Opera 8 before the WPM standard was complete.
 *
 *     dpm: postMessage on the document object.
 *        - Opera 8+
 */
gadgets.transports.Dpm = function() {
  var ready;
  return {
    getCode: function() {
      return 'dpm';
    },

    isParentVerifiable: function() {
      return false;
    },

    init: function(processFn, readyFn) {
      ready = readyFn;
      // Set up native postMessage handler.
      window.addEventListener('message', function(packet) {
        // TODO validate packet.domain for security reasons
        processFn(gadgets.json.parse(packet.data));
      }, false);
      ready('..', true);  // Ready immediately.
      return true;
    },

    setup: function(receiverId, token) {
      // See WPM setup comment.
      if (receiverId === '..') {
        gadgets.rpc.call(receiverId, gadgets.rpc.ACK);
      }
      return true;
    },

    call: function(targetId, from, rpc) {
      var targetDoc = targetId === '..' ? parent.document :
                                          frames[targetId].document;
      targetDoc.postMessage(gadgets.json.stringify(rpc));
      return true;
    }
  };
}();

/**
 * For Internet Explorer before version 8, the security model allows anyone
 * parent to set the value of the "opener" property on another window,
 * with only the receiving window able to read it.
 * This method is dubbed "Native IE XDC" (NIX).
 *
 * This method works by placing a handler object in the "opener" property
 * of a gadget when the container sets up the authentication information
 * for that gadget (by calling setAuthToken(...)). At that point, a NIX
 * wrapper is created and placed into the gadget by calling
 * theframe.contentWindow.opener = wrapper. Note that as a result, NIX can
 * only be used by a container to call a particular gadget *after* that
 * gadget has called the container at least once via NIX.
 *
 * The NIX wrappers in this RPC implementation are instances of a VBScript
 * class that is created when this implementation loads. The reason for
 * using a VBScript class stems from the fact that any object can be passed
 * into the opener property.
 * While this is a good thing, as it lets us pass functions and setup a true
 * bidirectional channel via callbacks, it opens a potential security hole
 * by which the other page can get ahold of the "window" or "document"
 * objects in the parent page and in turn wreak havok. This is due to the
 * fact that any JS object useful for establishing such a bidirectional
 * channel (such as a function) can be used to access a function
 * (eg. obj.toString, or a function itself) created in a specific context,
 * in particular the global context of the sender. Suppose container
 * domain C passes object obj to gadget on domain G. Then the gadget can
 * access C's global context using:
 * var parentWindow = (new obj.toString.constructor("return window;"))();
 * Nulling out all of obj's properties doesn't fix this, since IE helpfully
 * restores them to their original values if you do something like:
 * delete obj.toString; delete obj.toString;
 * Thus, we wrap the necessary functions and information inside a VBScript
 * object. VBScript objects in IE, like DOM objects, are in fact COM
 * wrappers when used in JavaScript, so we can safely pass them around
 * without worrying about a breach of context while at the same time
 * allowing them to act as a pass-through mechanism for information
 * and function calls. The implementation details of this VBScript wrapper
 * can be found in the setupChannel() method below.
 *
 *   nix: Internet Explorer-specific window.opener trick.
 *     - Internet Explorer 6
 *     - Internet Explorer 7
 */
gadgets.transports.Nix = function() {
  // Consts for NIX. VBScript doesn't
  // allow items to start with _ for some reason,
  // so we need to make these names quite unique, as
  // they will go into the global namespace.
  var NIX_WRAPPER = 'GRPC____NIXVBS_wrapper';
  var NIX_GET_WRAPPER = 'GRPC____NIXVBS_get_wrapper';
  var NIX_HANDLE_MESSAGE = 'GRPC____NIXVBS_handle_message';
  var NIX_CREATE_CHANNEL = 'GRPC____NIXVBS_create_channel';
  var MAX_NIX_SEARCHES = 10;
  var NIX_SEARCH_PERIOD = 500;

  // JavaScript reference to the NIX VBScript wrappers.
  // Gadgets will have but a single channel under
  // nix_channels['..'] while containers will have a channel
  // per gadget stored under the gadget's ID.
  var nix_channels = {};

  // Store the ready signal method for use on handshake complete.
  var ready;
  var numHandlerSearches = 0;

  // Search for NIX handler to parent. Tries MAX_NIX_SEARCHES times every
  // NIX_SEARCH_PERIOD milliseconds.
  function conductHandlerSearch() {
    // Call from gadget to the container.
    var handler = nix_channels['..'];
    if (handler) {
      return;
    }

    if (++numHandlerSearches > MAX_NIX_SEARCHES) {
      // Handshake failed. Will fall back.
      gadgets.warn('Nix transport setup failed, falling back...');
      ready('..', false);
      return;
    }

    // If the gadget has yet to retrieve a reference to
    // the NIX handler, try to do so now. We don't do a
    // typeof(window.opener.GetAuthToken) check here
    // because it means accessing that field on the COM object, which,
    // being an internal function reference, is not allowed.
    // "in" works because it merely checks for the prescence of
    // the key, rather than actually accessing the object's property.
    // This is just a sanity check, not a validity check.
    if (!handler && window.opener && "GetAuthToken" in window.opener) {
      handler = window.opener;

      // Create the channel to the parent/container.
      // First verify that it knows our auth token to ensure it's not
      // an impostor.
      if (handler.GetAuthToken() == gadgets.rpc.getAuthToken('..')) {
        // Auth match - pass it back along with our wrapper to finish.
        // own wrapper and our authentication token for co-verification.
        var token = gadgets.rpc.getAuthToken('..');
        handler.CreateChannel(window[NIX_GET_WRAPPER]('..', token),
                              token);
        // Set channel handler
        nix_channels['..'] = handler;
        window.opener = null;

        // Signal success and readiness to send to parent.
        // Container-to-gadget bit flipped in CreateChannel.
        ready('..', true);
        return;
      }
    }

    // Try again.
    window.setTimeout(function() { conductHandlerSearch(); },
                      NIX_SEARCH_PERIOD);
  }

  return {
    getCode: function() {
      return 'nix';
    },

    isParentVerifiable: function() {
      return false;
    },

    init: function(processFn, readyFn) {
      ready = readyFn;

      // Ensure VBScript wrapper code is in the page and that the
      // global Javascript handlers have been set.
      // VBScript methods return a type of 'unknown' when
      // checked via the typeof operator in IE. Fortunately
      // for us, this only applies to COM objects, so we
      // won't see this for a real Javascript object.
      if (typeof window[NIX_GET_WRAPPER] !== 'unknown') {
        window[NIX_HANDLE_MESSAGE] = function(data) {
          window.setTimeout(
              function() { processFn(gadgets.json.parse(data)) }, 0);
        };

        window[NIX_CREATE_CHANNEL] = function(name, channel, token) {
          // Verify the authentication token of the gadget trying
          // to create a channel for us.
          if (gadgets.rpc.getAuthToken(name) === token) {
            nix_channels[name] = channel;
            ready(name, true);
          }
        };

        // Inject the VBScript code needed.
        var vbscript =
          // We create a class to act as a wrapper for
          // a Javascript call, to prevent a break in of
          // the context.
          'Class ' + NIX_WRAPPER + '\n '

          // An internal member for keeping track of the
          // name of the document (container or gadget)
          // for which this wrapper is intended. For
          // those wrappers created by gadgets, this is not
          // used (although it is set to "..")
          + 'Private m_Intended\n'

          // Stores the auth token used to communicate with
          // the gadget. The GetChannelCreator method returns
          // an object that returns this auth token. Upon matching
          // that with its own, the gadget uses the object
          // to actually establish the communication channel.
          + 'Private m_Auth\n'

          // Method for internally setting the value
          // of the m_Intended property.
          + 'Public Sub SetIntendedName(name)\n '
          + 'If isEmpty(m_Intended) Then\n'
          + 'm_Intended = name\n'
          + 'End If\n'
          + 'End Sub\n'

          // Method for internally setting the value of the m_Auth property.
          + 'Public Sub SetAuth(auth)\n '
          + 'If isEmpty(m_Auth) Then\n'
          + 'm_Auth = auth\n'
          + 'End If\n'
          + 'End Sub\n'

          // A wrapper method which actually causes a
          // message to be sent to the other context.
          + 'Public Sub SendMessage(data)\n '
          + NIX_HANDLE_MESSAGE + '(data)\n'
          + 'End Sub\n'

          // Returns the auth token to the gadget, so it can
          // confirm a match before initiating the connection
          + 'Public Function GetAuthToken()\n '
          + 'GetAuthToken = m_Auth\n'
          + 'End Function\n'

          // Method for setting up the container->gadget
          // channel. Not strictly needed in the gadget's
          // wrapper, but no reason to get rid of it. Note here
          // that we pass the intended name to the NIX_CREATE_CHANNEL
          // method so that it can save the channel in the proper place
          // *and* verify the channel via the authentication token passed
          // here.
          + 'Public Sub CreateChannel(channel, auth)\n '
          + 'Call ' + NIX_CREATE_CHANNEL + '(m_Intended, channel, auth)\n'
          + 'End Sub\n'
          + 'End Class\n'

          // Function to get a reference to the wrapper.
          + 'Function ' + NIX_GET_WRAPPER + '(name, auth)\n'
          + 'Dim wrap\n'
          + 'Set wrap = New ' + NIX_WRAPPER + '\n'
          + 'wrap.SetIntendedName name\n'
          + 'wrap.SetAuth auth\n'
          + 'Set ' + NIX_GET_WRAPPER + ' = wrap\n'
          + 'End Function';

        try {
          window.execScript(vbscript, 'vbscript');
        } catch (e) {
          return false;
        }
      }
      return true;
    },

    setup: function(receiverId, token) {
      if (receiverId === '..') {
        conductHandlerSearch();
        return true;
      }
      try {
        var frame = document.getElementById(receiverId);
        var wrapper = window[NIX_GET_WRAPPER](receiverId, token);
        frame.contentWindow.opener = wrapper;
      } catch (e) {
        return false;
      }
      return true;
    },

    call: function(targetId, from, rpc) {
      try {
        // If we have a handler, call it.
        if (nix_channels[targetId]) {
          nix_channels[targetId].SendMessage(gadgets.json.stringify(rpc));
        }
      } catch (e) {
        return false;
      }
      return true;
    }
  };
}();

/*
 * For Gecko-based browsers, the security model allows a child to call a
 * function on the frameElement of the iframe, even if the child is in
 * a different domain. This method is dubbed "frameElement" (fe).
 *
 * The ability to add and call such functions on the frameElement allows
 * a bidirectional channel to be setup via the adding of simple function
 * references on the frameElement object itself. In this implementation,
 * when the container sets up the authentication information for that gadget
 * (by calling setAuth(...)) it as well adds a special function on the
 * gadget's iframe. This function can then be used by the gadget to send
 * messages to the container. In turn, when the gadget tries to send a
 * message, it checks to see if this function has its own function stored
 * that can be used by the container to call the gadget. If not, the
 * function is created and subsequently used by the container.
 * Note that as a result, FE can only be used by a container to call a
 * particular gadget *after* that gadget has called the container at
 * least once via FE.
 *
 *   fe: Gecko-specific frameElement trick.
 *      - Firefox 1+
 */
gadgets.transports.FrameElement = function() {
  // Consts for FrameElement.
  var FE_G2C_CHANNEL = '__g2c_rpc';
  var FE_C2G_CHANNEL = '__c2g_rpc';
  var process;
  var ready;

  function callFrameElement(targetId, from, rpc) {
    try {
      if (from !== '..') {
        // Call from gadget to the container.
        var fe = window.frameElement;

        if (typeof fe[FE_G2C_CHANNEL] === 'function') {
          // Complete the setup of the FE channel if need be.
          if (typeof fe[FE_G2C_CHANNEL][FE_C2G_CHANNEL] !== 'function') {
            fe[FE_G2C_CHANNEL][FE_C2G_CHANNEL] = function(args) {
              process(gadgets.json.parse(args));
            };
          }

          // Conduct the RPC call.
          fe[FE_G2C_CHANNEL](gadgets.json.stringify(rpc));
          return;
        }
      } else {
        // Call from container to gadget[targetId].
        var frame = document.getElementById(targetId);

        if (typeof frame[FE_G2C_CHANNEL] === 'function' &&
            typeof frame[FE_G2C_CHANNEL][FE_C2G_CHANNEL] === 'function') {

          // Conduct the RPC call.
          frame[FE_G2C_CHANNEL][FE_C2G_CHANNEL](gadgets.json.stringify(rpc));
          return;
        }
      }
    } catch (e) {
      return false;
    }
    return true;
  }

  return {
    getCode: function() {
      return 'fe';
    },

    isParentVerifiable: function() {
      return false;
    },
  
    init: function(processFn, readyFn) {
      // No global setup.
      process = processFn;
      ready = readyFn;
      return true;
    },

    setup: function(receiverId, token) {
      // Indicate OK to call to container. This will be true
      // by the end of this method.
      if (receiverId !== '..') {
        try {
          var frame = document.getElementById(receiverId);
          frame[FE_G2C_CHANNEL] = function(args) {
            process(gadgets.json.parse(args));
          };
        } catch (e) {
          return false;
        }
      }
      if (receiverId === '..') {
        ready('..', true);
        var ackFn = function() {
          window.setTimeout(function() {
            gadgets.rpc.call(receiverId, gadgets.rpc.ACK)
          }, 0);
        }
        if (document.body) {
          // TODO Consider moving document.body check to registerOnLoadHandler
          ackFn();
        } else {
          gadgets.util.registerOnLoadHandler(ackFn);
        }
      }
      return true;
    },

    call: function(targetId, from, rpc) {
      callFrameElement(targetId, from, rpc);
    } 

  };
}();

/*
 * For older WebKit-based browsers, the security model does not allow for any
 * known "native" hacks for conducting cross browser communication. However,
 * a variation of the IFPC (see below) can be used, entitled "RMR". RMR is
 * a technique that uses the resize event of the iframe to indicate that a
 * message was sent (instead of the much slower/performance heavy polling
 * technique used when a defined relay page is not avaliable). Simply put,
 * RMR uses the same "pass the message by the URL hash" trick that IFPC
 * uses to send a message, but instead of having an active relay page that
 * runs a piece of code when it is loaded, RMR merely changes the URL
 * of the relay page (which does not even have to exist on the domain)
 * and then notifies the other party by resizing the relay iframe. RMR
 * exploits the fact that iframes in the dom of page A can be resized
 * by page A while the onresize event will be fired in the DOM of page B,
 * thus providing a single bit channel indicating "message sent to you".
 * This method has the added benefit that the relay need not be active,
 * nor even exist: a 404 suffices just as well.
 *
 *   rmr: WebKit-specific resizing trick.
 *      - Safari 2+
 *      - Chrome 1
 */
gadgets.transports.Rmr = function() {
  // Consts for RMR, including time in ms RMR uses to poll for
  // its relay frame to be created, and the max # of polls it does.
  var RMR_SEARCH_TIMEOUT = 500;
  var RMR_MAX_POLLS = 10;

  // JavaScript references to the channel objects used by RMR.
  // Gadgets will have but a single channel under
  // rmr_channels['..'] while containers will have a channel
  // per gadget stored under the gadget's ID.
  var rmr_channels = {};
  
  var process;
  var ready;

  /**
   * Append an RMR relay frame to the document. This allows the receiver
   * to start receiving messages.
   *
   * @param {object} channelFrame Relay frame to add to the DOM body.
   * @param {string} relayUri Base URI for the frame.
   * @param {string} Data to pass along to the frame.
   */
  function appendRmrFrame(channelFrame, relayUri, data) {
    var appendFn = function() {
      // Append the iframe.
      document.body.appendChild(channelFrame);

      // Set the src of the iframe to 'about:blank' first and then set it
      // to the relay URI. This prevents the iframe from maintaining a src
      // to the 'old' relay URI if the page is returned to from another.
      // In other words, this fixes the bfcache issue that causes the iframe's
      // src property to not be updated despite us assigning it a new value here.
      channelFrame.src = 'about:blank';
      channelFrame.src = relayUri + '#' + data;
    }

    if (document.body) {
      appendFn();
    } else {
      // Common gadget case: attaching header during in-gadget handshake,
      // when we may still be in script in head. Attach onload.
      gadgets.util.registerOnLoadHandler(function() { appendFn(); });
    }
  }

  /**
   * Sets up the RMR transport frame for the given frameId. For gadgets
   * calling containers, the frameId should be '..'.
   *
   * @param {string} frameId The ID of the frame.
   */
  function setupRmr(frameId) {
    if (typeof rmr_channels[frameId] === "object") {
      // Sanity check. Already done.
      return;
    }

    var channelFrame = document.createElement('iframe');
    var frameStyle = channelFrame.style;
    frameStyle.position = 'absolute';
    frameStyle.top = '0px';
    frameStyle.border = '0';
    frameStyle.opacity = '0';

    // The width here is important as RMR
    // makes use of the resize handler for the frame.
    // Do not modify unless you test thoroughly!
    frameStyle.width = '10px'
    frameStyle.height = '1px';
    channelFrame.id = 'rmrtransport-' + frameId;
    channelFrame.name = channelFrame.id;

    // Determine the relay uri by taking the existing one,
    // removing the path and appending robots.txt. It is
    // not important if robots.txt actually exists, since RMR
    // browsers treat 404s as legitimate for the purposes of
    // this communication.
    var relayUri =
        gadgets.rpc.getDomainRoot(gadgets.rpc.getRelayUrl(frameId)) + '/robots.txt';

    rmr_channels[frameId] = {
      frame: channelFrame,
      receiveWindow: null,
      relayUri: relayUri,
      searchCounter : 0,
      width: 10,

      // Waiting means "waiting for acknowledgement to be received."
      // Acknowledgement always comes as a special ACK
      // message having been received. This message is received
      // during handshake in different ways by the container and
      // gadget, and by normal RMR message passing once the handshake
      // is complete.
      waiting: true,
      queue: [],

      // Number of non-ACK messages that have been sent to the recipient
      // and have been acknowledged.
      sendId: 0,

      // Number of messages received and processed from the sender.
      // This is the number that accompanies every ACK to tell the
      // sender to clear its queue.
      recvId: 0
    };

    if (frameId !== '..') {
      // Container always appends a relay to the gadget, before
      // the gadget appends its own relay back to container. The
      // gadget, in the meantime, refuses to attach the container
      // relay until it finds this one. Thus, the container knows
      // for certain that gadget to container communication is set
      // up by the time it finds its own relay. In addition to
      // establishing a reliable handshake protocol, this also
      // makes it possible for the gadget to send an initial batch
      // of messages to the container ASAP.
      appendRmrFrame(channelFrame, relayUri, getRmrData(frameId));
    }
     
    // Start searching for our own frame on the other page.
    conductRmrSearch(frameId);
  }

  /**
   * Searches for a relay frame, created by the sender referenced by
   * frameId, with which this context receives messages. Once
   * found with proper permissions, attaches a resize handler which
   * signals messages to be sent.
   *
   * @param {string} frameId Frame ID of the prospective sender.
   */
  function conductRmrSearch(frameId) {
    var channelWindow = null;

    // Increment the search counter.
    rmr_channels[frameId].searchCounter++;

    if (frameId === '..') {
      // We are a gadget.
      channelWindow = window.parent.frames['rmrtransport-' + window.name];
    } else {
      // We are a container.
      channelWindow = window.frames[frameId].frames['rmrtransport-..'];
    }

    var status = false;

    if (channelWindow) {
      // We have a valid reference to "our" RMR transport frame.
      // Register the proper event handlers.
      status = registerRmrChannel(frameId, channelWindow);
    }

    if (!status) {
      // Not found yet. Continue searching, but only if the counter
      // has not reached the threshold.
      if (rmr_channels[frameId].searchCounter > RMR_MAX_POLLS) {
        // If we reach this point, then RMR has failed and we
        // fall back to IFPC.
        return;
      }

      setTimeout(function() {
        conductRmrSearch(frameId);
      }, RMR_SEARCH_TIMEOUT);
    }
  }

  /**
   * Attempts to conduct an RPC call to the specified
   * target with the specified data via the RMR
   * method. If this method fails, the system attempts again
   * using the known default of IFPC.
   *
   * @param {String} targetId Module Id of the RPC service provider.
   * @param {String} serviceName Name of the service to call.
   * @param {String} from Module Id of the calling provider.
   * @param {Object} rpc The RPC data for this call.
   */
  function callRmr(targetId, serviceName, from, rpc) {
    var handler = null;

    if (from !== '..') {
      // Call from gadget to the container.
      handler = rmr_channels['..'];
    } else {
      // Call from container to the gadget.
      handler = rmr_channels[targetId];
    }

    if (handler) {
      // Queue the current message if not ACK.
      // ACK is always sent through getRmrData(...).
      if (serviceName !== gadgets.rpc.ACK) {
        handler.queue.push(rpc);
      }

      if (handler.waiting ||
          (handler.queue.length === 0 &&
           !(serviceName === gadgets.rpc.ACK && rpc && rpc.ackAlone === true))) {
        // If we are awaiting a response from any previously-sent messages,
        // or if we don't have anything new to send, just return.
        // Note that we don't short-return if we're ACKing just-received
        // messages.
        return true;
      }

      if (handler.queue.length > 0) {
        handler.waiting = true;
      }

      var url = handler.relayUri + "#" + getRmrData(targetId);

      try {
        // Update the URL with the message.
        handler.frame.contentWindow.location = url;

        // Resize the frame.
        var newWidth = handler.width == 10 ? 20 : 10;
        handler.frame.style.width = newWidth + 'px';
        handler.width = newWidth;

        // Done!
      } catch (e) {
        // Something about location-setting or resizing failed.
        // This should never happen, but if it does, fall back to
        // the default transport.
        return false;
      }
    }

    return true;
  }

  /**
   * Returns as a string the data to be appended to an RMR relay frame,
   * constructed from the current request queue plus an ACK message indicating
   * the currently latest-processed message ID.
   *
   * @param {string} toFrameId Frame whose sendable queued data to retrieve.
   */
  function getRmrData(toFrameId) {
    var channel = rmr_channels[toFrameId];
    var rmrData = {id: channel.sendId};
    if (channel) {
      rmrData.d = Array.prototype.slice.call(channel.queue, 0);
      rmrData.d.push({s:gadgets.rpc.ACK, id:channel.recvId});
    }
    return gadgets.json.stringify(rmrData);
  }

  /**
   * Retrieve data from the channel keyed by the given frameId,
   * processing it as a batch. All processed data is assumed to have been
   * generated by getRmrData(...), pairing that method with this.
   *
   * @param {string} fromFrameId Frame from which data is being retrieved.
   */
  function processRmrData(fromFrameId) {
    var channel = rmr_channels[fromFrameId];
    var data = channel.receiveWindow.location.hash.substring(1);

    // Decode the RPC object array.
    var rpcObj = gadgets.json.parse(decodeURIComponent(data)) || {};
    var rpcArray = rpcObj.d || [];

    var nonAckReceived = false;
    var noLongerWaiting = false;

    var numBypassed = 0;
    var numToBypass = (channel.recvId - rpcObj.id);
    for (var i = 0; i < rpcArray.length; ++i) {
      var rpc = rpcArray[i];

      // If we receive an ACK message, then mark the current
      // handler as no longer waiting and send out the next
      // queued message.
      if (rpc.s === gadgets.rpc.ACK) {
        // ACK received - whether this came from a handshake or
        // an active call, in either case it indicates readiness to
        // send messages to the from frame.
        ready(fromFrameId, true);

        if (channel.waiting) {
          noLongerWaiting = true;
        }

        channel.waiting = false;
        var newlyAcked = Math.max(0, rpc.id - channel.sendId);
        channel.queue.splice(0, newlyAcked);
        channel.sendId = Math.max(channel.sendId, rpc.id || 0);
        continue;
      }

      // If we get here, we've received > 0 non-ACK messages to
      // process. Indicate this bit for later.
      nonAckReceived = true;

      // Bypass any messages already received.
      if (++numBypassed <= numToBypass) {
        continue;
      }

      ++channel.recvId;
      process(rpc);  // actually dispatch the message
    }

    // Send an ACK indicating that we got/processed the message(s).
    // Do so if we've received a message to process or if we were waiting
    // before but a received ACK has cleared our waiting bit, and we have
    // more messages to send. Performing this operation causes additional
    // messages to be sent.
    if (nonAckReceived ||
        (noLongerWaiting && channel.queue.length > 0)) {
      var from = (fromFrameId === '..') ? window.name : '..';
      callRmr(fromFrameId, gadgets.rpc.ACK, from, {ackAlone: nonAckReceived});
    }
  }

  /**
   * Registers the RMR channel handler for the given frameId and associated
   * channel window.
   *
   * @param {string} frameId The ID of the frame for which this channel is being
   *   registered.
   * @param {Object} channelWindow The window of the receive frame for this
   *   channel, if any.
   *
   * @return {boolean} True if the frame was setup successfully, false
   *   otherwise.
   */
  function registerRmrChannel(frameId, channelWindow) {
    var channel = rmr_channels[frameId];

    // Verify that the channel is ready for receiving.
    try {
      var canAccess = false;

      // Check to see if the document is in the window. For Chrome, this
      // will return 'false' if the channelWindow is inaccessible by this
      // piece of JavaScript code, meaning that the URL of the channelWindow's
      // parent iframe has not yet changed from 'about:blank'. We do this
      // check this way because any true *access* on the channelWindow object
      // will raise a security exception, which, despite the try-catch, still
      // gets reported to the debugger (it does not break execution, the try
      // handles that problem, but it is still reported, which is bad form).
      // This check always succeeds in Safari 3.1 regardless of the state of
      // the window.
      canAccess = 'document' in channelWindow;

      if (!canAccess) {
        return false;
      }

      // Check to see if the document is an object. For Safari 3.1, this will
      // return undefined if the page is still inaccessible. Unfortunately, this
      // *will* raise a security issue in the debugger.
      // TODO Find a way around this problem.
      canAccess = typeof channelWindow['document'] == 'object';

      if (!canAccess) {
        return false;
      }

      // Once we get here, we know we can access the document (and anything else)
      // on the window object. Therefore, we check to see if the location is
      // still about:blank (this takes care of the Safari 3.2 case).
      var loc = channelWindow.location.href;

      // Check if this is about:blank for Safari.
      if (loc === 'about:blank') {
        return false;
      }
    } catch (ex) {
      // For some reason, the iframe still points to about:blank. We try
      // again in a bit.
      return false;
    }

    // Save a reference to the receive window.
    channel.receiveWindow = channelWindow;

    // Register the onresize handler.
    channelWindow.onresize = function() {
      processRmrData(frameId);
    };

    if (frameId === '..') {
      // Gadget to container. Signal to the container that the gadget
      // is ready to receive messages by attaching the g -> c relay.
      // As a nice optimization, pass along any gadget to container
      // queued messages that have backed up since then. ACK is enqueued in
      // getRmrData to ensure that the container's waiting flag is set to false
      // (this happens in the below code run on the container side).
      appendRmrFrame(channel.frame, channel.relayUri, getRmrData(frameId));
    }

    // Attempt to process the messages that the other party may have set in
    // the resize frame's hash. For gadget to container, this is the gadget
    // finding the container-set IFRAME, which has an ACK attached to it.
    // For gadget to container, the gadget may have enqueued messages already,
    // and sent them in the above code. This too will have an ACK message.
    // The net effect is that both sides of the connection will have their
    // "waiting" bit set to false, so they're ready to send messages.
    processRmrData(frameId);

    return true;
  }

  return {
    getCode: function() {
      return 'rmr';
    },

    isParentVerifiable: function() {
      return true;
    },

    init: function(processFn, readyFn) {
      // No global setup.
      process = processFn;
      ready = readyFn;
      return true;
    },

    setup: function(receiverId, token) {
      try {
        setupRmr(receiverId);
      } catch (e) {
        gadgets.warn('Caught exception setting up RMR: ' + e);
        return false;
      }
      return true;
    },

    call: function(targetId, from, rpc) {
      return callRmr(targetId, rpc.s, from, rpc);
    }
  };
}();

/*
 * For all others, we have a fallback mechanism known as "ifpc". IFPC
 * exploits the fact that while same-origin policy prohibits a frame from
 * accessing members on a window not in the same domain, that frame can,
 * however, navigate the window heirarchy (via parent). This is exploited by
 * having a page on domain A that wants to talk to domain B create an iframe
 * on domain B pointing to a special relay file and with a message encoded
 * after the hash (#). This relay, in turn, finds the page on domain B, and
 * can call a receipt function with the message given to it. The relay URL
 * used by each caller is set via the gadgets.rpc.setRelayUrl(..) and
 * *must* be called before the call method is used.
 *
 *   ifpc: Iframe-based method, utilizing a relay page, to send a message.
 *      - No known major browsers still use this method, but it remains
 *        useful as a catch-all fallback for the time being.
 */
gadgets.transports.Ifpc = function() {
  var iframePool = [];
  var callId = 0;
  var ready;

  /**
   * Encodes arguments for the legacy IFPC wire format.
   *
   * @param {Object} args
   * @return {String} the encoded args
   */
  function encodeLegacyData(args) {
    var argsEscaped = [];
    for(var i = 0, j = args.length; i < j; ++i) {
      argsEscaped.push(encodeURIComponent(gadgets.json.stringify(args[i])));
    }
    return argsEscaped.join('&');
  }

  /**
   * Helper function to emit an invisible IFrame.
   * @param {String} src SRC attribute of the IFrame to emit.
   * @private
   */
  function emitInvisibleIframe(src) {
    var iframe;
    // Recycle IFrames
    for (var i = iframePool.length - 1; i >=0; --i) {
      var ifr = iframePool[i];
      try {
        if (ifr && (ifr.recyclable || ifr.readyState === 'complete')) {
          ifr.parentNode.removeChild(ifr);
          if (window.ActiveXObject) {
            // For MSIE, delete any iframes that are no longer being used. MSIE
            // cannot reuse the IFRAME because a navigational click sound will
            // be triggered when we set the SRC attribute.
            // Other browsers scan the pool for a free iframe to reuse.
            iframePool[i] = ifr = null;
            iframePool.splice(i, 1);
          } else {
            ifr.recyclable = false;
            iframe = ifr;
            break;
          }
        }
      } catch (e) {
        // Ignore; IE7 throws an exception when trying to read readyState and
        // readyState isn't set.
      }
    }
    // Create IFrame if necessary
    if (!iframe) {
      iframe = document.createElement('iframe');
      iframe.style.border = iframe.style.width = iframe.style.height = '0px';
      iframe.style.visibility = 'hidden';
      iframe.style.position = 'absolute';
      iframe.onload = function() { this.recyclable = true; };
      iframePool.push(iframe);
    }
    iframe.src = src;
    setTimeout(function() { document.body.appendChild(iframe); }, 0);
  }

  return {
    getCode: function() {
      return 'ifpc';
    },

    isParentVerifiable: function() {
      return true;
    },

    init: function(processFn, readyFn) {
      // No global setup.
      ready = readyFn;
      ready('..', true);  // Ready immediately.
      return true;
    },

    setup: function(receiverId, token) {
      // Indicate readiness to send to receiver.
      ready(receiverId, true);
      return true;
    },

    call: function(targetId, from, rpc) {
      // Retrieve the relay file used by IFPC. Note that
      // this must be set before the call, and so we conduct
      // an extra check to ensure it is not blank.
      var relay = gadgets.rpc.getRelayUrl(targetId);
      ++callId;

      if (!relay) {
        gadgets.warn('No relay file assigned for IFPC');
        return;
      }

      // The RPC mechanism supports two formats for IFPC (legacy and current).
      var src = null;
      if (rpc.l) {
        // Use legacy protocol.
        // Format: #iframe_id&callId&num_packets&packet_num&block_of_data
        var callArgs = rpc.a;
        src = [relay, '#', encodeLegacyData([from, callId, 1, 0,
               encodeLegacyData([from, serviceName, '', '', from].concat(
                 callArgs))])].join('');
      } else {
        // Format: #targetId & sourceId@callId & packetNum & packetId & packetData
        src = [relay, '#', targetId, '&', from, '@', callId,
               '&1&0&', encodeURIComponent(gadgets.json.stringify(rpc))].join('');
      }

      // Conduct the IFPC call by creating the Iframe with
      // the relay URL and appended message.
      emitInvisibleIframe(src);
      return true;
    }
  };
}();

/**
 * @static
 * @class Provides operations for making rpc calls.
 * @name gadgets.rpc
 */
gadgets.rpc = function() {
  // General constants.
  var CALLBACK_NAME = '__cb';
  var DEFAULT_NAME = '';

  // Special service name for acknowledgements.
  var ACK = '__ack';

  var services = {};
  var relayUrl = {};
  var useLegacyProtocol = {};
  var authToken = {};
  var callId = 0;
  var callbacks = {};
  var setup = {};
  var sameDomain = {};
  var params = {};
  var receiverTx = {};
  var earlyRpcQueue = {};
  var isGadget = false;
  var fallbackTransport = gadgets.transports.Ifpc;

  // Load the authentication token for speaking to the container
  // from the gadget's parameters, or default to '0' if not found.
  if (gadgets.util) {
    params = gadgets.util.getUrlParameters();
  }

  authToken['..'] = params.rpctoken || params.ifpctok || 0;

  /*
   * Return a transport representing the best available cross-domain
   * message-passing mechanism available to the browser.
   *
   * Transports are selected on a cascading basis determined by browser
   * capability and other checks. The order of preference is:
   * 1. wpm: Uses window.postMessage standard.
   * 2. dpm: Uses document.postMessage, similar to wpm but pre-standard.
   * 3. nix: Uses IE-specific browser hacks.
   * 4. rmr: Signals message passing using relay file's onresize handler.
   * 5. fe: Uses FF2-specific window.frameElement hack.
   * 6. ifpc: Sends messages via active load of a relay file.
   *
   * See each transport's commentary/documentation for details.
   */
  function getTransport() {
    return typeof window.postMessage === 'function' ? gadgets.transports.Wpm :
           typeof document.postMessage === 'function' ? gadgets.transports.Dpm :
           window.ActiveXObject ? gadgets.transports.Nix :
           navigator.userAgent.indexOf('WebKit') > 0 ? gadgets.transports.Rmr :
           navigator.product === 'Gecko' ? gadgets.transports.FrameElement :
           gadgets.transports.Ifpc;
  }

  /**
   * Function passed to, and called by, a transport indicating it's ready to
   * send and receive messages.
   */
  function transportReady(receiverId, readySuccess) {
    var tx = transport;
    if (!readySuccess) {
      tx = fallbackTransport;
    }
    receiverTx[receiverId] = tx;

    // If there are any early-queued messages, send them now directly through
    // the needed transport.
    var earlyQueue = earlyRpcQueue[receiverId] || [];
    for (var i = 0; i < earlyQueue.length; ++i) {
      var rpc = earlyQueue[i];
      // There was no auth/rpc token set before, so set it now.
      rpc.t = gadgets.rpc.getAuthToken(receiverId);
      tx.call(receiverId, rpc.f, rpc);
    }

    // Clear the queue so it won't be sent again.
    earlyRpcQueue[receiverId] = [];
  }

  /**
   * Helper function to process an RPC request
   * @param {Object} rpc RPC request object
   * @private
   */
  function process(rpc) {
    //
    // RPC object contents:
    //   s: Service Name
    //   f: From
    //   c: The callback ID or 0 if none.
    //   a: The arguments for this RPC call.
    //   t: The authentication token.
    //
    if (rpc && typeof rpc.s === 'string' && typeof rpc.f === 'string' &&
        rpc.a instanceof Array) {

      // Validate auth token.
      if (authToken[rpc.f]) {
        // We don't do type coercion here because all entries in the authToken
        // object are strings, as are all url params. See setAuthToken(...).
        if (authToken[rpc.f] !== rpc.t) {
          throw new Error("Invalid auth token. " +
              authToken[rpc.f] + " vs " + rpc.t);
        }
      }

      if (rpc.s === ACK) {
        // Acknowledgement API, used to indicate a receiver is ready.
        window.setTimeout(function() { transportReady(rpc.f, true); }, 0);
        return;
      }

      // If there is a callback for this service, attach a callback function
      // to the rpc context object for asynchronous rpc services.
      //
      // Synchronous rpc request handlers should simply ignore it and return a
      // value as usual.
      // Asynchronous rpc request handlers, on the other hand, should pass its
      // result to this callback function and not return a value on exit.
      //
      // For example, the following rpc handler passes the first parameter back
      // to its rpc client with a one-second delay.
      //
      // function asyncRpcHandler(param) {
      //   var me = this;
      //   setTimeout(function() {
      //     me.callback(param);
      //   }, 1000);
      // }
      if (rpc.c) {
        rpc.callback = function(result) {
          gadgets.rpc.call(rpc.f, CALLBACK_NAME, null, rpc.c, result);
        };
      }

      // Call the requested RPC service.
      var result = (services[rpc.s] ||
                    services[DEFAULT_NAME]).apply(rpc, rpc.a);

      // If the rpc request handler returns a value, immediately pass it back
      // to the callback. Otherwise, do nothing, assuming that the rpc handler
      // will make an asynchronous call later.
      if (rpc.c && typeof result !== 'undefined') {
        gadgets.rpc.call(rpc.f, CALLBACK_NAME, null, rpc.c, result);
      }
    }
  }

  /**
   * Helper method returning a canonicalized schema://host[:port] for
   * a given input URL, provided as a string. Used to compute convenient
   * relay URLs and to determine whether a call is coming from the same
   * domain as its receiver (bypassing the try/catch capability detection
   * flow, thereby obviating Firebug and other tools reporting an exception).
   *
   * @param {string} url Base URL to canonicalize.
   */
  function getDomainRoot(url) {
    if (!url) {
      return "";
    }
    url = url.toLowerCase();
    if (url.indexOf("//") == 0) {
      url = window.location.protocol + ":" + url;
    }
    if (url.indexOf("http://") != 0 &&
        url.indexOf("https://") != 0) {
      // Assumed to be schemaless. Default to current protocol.
      url = window.location.protocol + "://" + url;
    }
    // At this point we guarantee that "://" is in the URL and defines
    // current protocol. Skip past this to search for host:port.
    var host = url.substring(url.indexOf("://") + 3);

    // Find the first slash char, delimiting the host:port.
    var slashPos = host.indexOf("/");
    if (slashPos != -1) {
      host = host.substring(0, slashPos);
    }

    var protocol = url.substring(0, url.indexOf("://"));

    // Use port only if it's not default for the protocol.
    var portStr = "";
    var portPos = host.indexOf(":");
    if (portPos != -1) {
      var port = host.substring(portPos + 1);
      host = host.substring(0, portPos);
      if ((protocol === "http" && port !== "80") ||
          (protocol === "https" && port !== "443")) {
        portStr = ":" + port;
      }
    }

    // Return <protocol>://<host>[<port>]
    return protocol + "://" + host + portStr;
  }

  // Pick the most efficient RPC relay mechanism.
  var transport = getTransport();

  // Create the Default RPC handler.
  services[DEFAULT_NAME] = function() {
    gadgets.warn('Unknown RPC service: ' + this.s);
  };

  // Create a Special RPC handler for callbacks.
  services[CALLBACK_NAME] = function(callbackId, result) {
    var callback = callbacks[callbackId];
    if (callback) {
      delete callbacks[callbackId];
      callback(result);
    }
  };

  /**
   * Conducts any frame-specific work necessary to setup
   * the channel type chosen. This method is called when
   * the container page first registers the gadget in the
   * RPC mechanism. Gadgets, in turn, will complete the setup
   * of the channel once they send their first messages.
   */
  function setupFrame(frameId, token) {
    if (setup[frameId]) {
      return;
    }

    if (transport.setup(frameId, token) === false) {
      transport = fallbackTransport;
    }

    setup[frameId] = true;
  }

  /**
   * Attempts to make an rpc by calling the target's receive method directly.
   * This works when gadgets are rendered on the same domain as their container,
   * a potentially useful optimization for trusted content which keeps
   * RPC behind a consistent interface.
   * @param {String} target Module id of the rpc service provider
   * @param {String} from Module id of the caller (this)
   * @param {String} callbackId Id of the call
   * @param {String} rpcData JSON-encoded RPC payload
   * @return
   */
  function callSameDomain(target, rpc) {
    if (typeof sameDomain[target] === 'undefined') {
      // Seed with a negative, typed value to avoid
      // hitting this code path repeatedly.
      sameDomain[target] = false;
      var targetRelay = gadgets.rpc.getRelayUrl(target);
      if (getDomainRoot(targetRelay) !== getDomainRoot(window.location.href)) {
        // Not worth trying -- avoid the error and just return.
        return false;
      }

      var targetEl = null;
      if (target === '..') {
        targetEl = parent;
      } else {
        targetEl = frames[target];
      }
      try {
        // If this succeeds, then same-domain policy applied
        sameDomain[target] = targetEl.gadgets.rpc.receiveSameDomain;
      } catch (e) {
        // Shouldn't happen due to domain root check. Caught just in case.
        gadgets.warn("Unexpected: same domain call failed.");
      }
    }

    if (typeof sameDomain[target] === 'function') {
      // Call target's receive method
      sameDomain[target](rpc);
      return true;
    }

    return false;
  }

  // gadgets.config might not be available, such as when serving container js.
  if (gadgets.config) {
    /**
     * Initializes RPC from the provided configuration.
     */
    function init(config) {
      // Allow for wild card parent relay files as long as it's from a
      // white listed domain. This is enforced by the rendering servlet.
      if (config.rpc.parentRelayUrl.substring(0, 7) === 'http://' ||
          config.rpc.parentRelayUrl.substring(0, 8) === 'https://' ||
          config.rpc.parentRelayUrl.substring(0, 2) === '//') {
        relayUrl['..'] = config.rpc.parentRelayUrl;
      } else {
        // It's a relative path, and we must append to the parent.
        // We're relying on the server validating the parent parameter in this
        // case. Because of this, parent may only be passed in the query, not
        // the fragment.
        var params = document.location.search.substring(1).split("&");
        var parentParam = "";
        for (var i = 0, param; (param = params[i]); ++i) {
          // Only the first parent can be validated.
          if (param.indexOf("parent=") === 0) {
            parentParam = decodeURIComponent(param.substring(7));
            break;
          }
        }
        if (parentParam !== "") {
          // Otherwise, relayUrl['..'] will be null, signaling transport
          // code to ignore rpc calls since they cannot work without a
          // relay URL with host qualification.
          relayUrl['..'] = parentParam + config.rpc.parentRelayUrl;

          // We assume that any rendering context where gadgets.config
          // is defined and a parent param is provided (gets here) is a gadget.
          isGadget = true;
        }
      }
      useLegacyProtocol['..'] = !!config.rpc.useLegacyProtocol;
    }

    var requiredConfig = {
      parentRelayUrl : gadgets.config.NonEmptyStringValidator
    };
    gadgets.config.register("rpc", requiredConfig, init);
  }

  return /** @scope gadgets.rpc */ {
    /**
     * Registers an RPC service.
     * @param {String} serviceName Service name to register.
     * @param {Function} handler Service handler.
     *
     * @member gadgets.rpc
     */
    register: function(serviceName, handler) {
      if (serviceName === CALLBACK_NAME || serviceName === ACK) {
        throw new Error("Cannot overwrite callback/ack service");
      }

      if (serviceName === DEFAULT_NAME) {
        throw new Error("Cannot overwrite default service:"
                        + " use registerDefault");
      }

      services[serviceName] = handler;
    },

    /**
     * Unregisters an RPC service.
     * @param {String} serviceName Service name to unregister.
     *
     * @member gadgets.rpc
     */
    unregister: function(serviceName) {
      if (serviceName === CALLBACK_NAME || serviceName === ACK) {
        throw new Error("Cannot delete callback/ack service");
      }

      if (serviceName === DEFAULT_NAME) {
        throw new Error("Cannot delete default service:"
                        + " use unregisterDefault");
      }

      delete services[serviceName];
    },

    /**
     * Registers a default service handler to processes all unknown
     * RPC calls which raise an exception by default.
     * @param {Function} handler Service handler.
     *
     * @member gadgets.rpc
     */
    registerDefault: function(handler) {
      services[DEFAULT_NAME] = handler;
    },

    /**
     * Unregisters the default service handler. Future unknown RPC
     * calls will fail silently.
     *
     * @member gadgets.rpc
     */
    unregisterDefault: function() {
      delete services[DEFAULT_NAME];
    },

    /**
     * Forces all subsequent calls to be made by a transport
     * method that allows the caller to verify the message receiver
     * (by way of the parent parameter, through getRelayUrl(...)).
     * At present this means IFPC or WPM.
     */
    forceParentVerifiable: function() {
      if (!transport.isParentVerifiable()) {
        transport = gadgets.transports.Ifpc;
      }
    },

    /**
     * Calls an RPC service.
     * @param {String} targetId Module Id of the RPC service provider.
     *                          Empty if calling the parent container.
     * @param {String} serviceName Service name to call.
     * @param {Function|null} callback Callback function (if any) to process
     *                                 the return value of the RPC request.
     * @param {*} var_args Parameters for the RPC request.
     *
     * @member gadgets.rpc
     */
    call: function(targetId, serviceName, callback, var_args) {
      targetId = targetId || '..';
      // Default to the container calling.
      var from = '..';

      if (targetId === '..') {
        from = window.name;
      }

      ++callId;
      if (callback) {
        callbacks[callId] = callback;
      }

      var rpc = {
        s: serviceName,
        f: from,
        c: callback ? callId : 0,
        a: Array.prototype.slice.call(arguments, 3),
        t: authToken[targetId],
        l: useLegacyProtocol[targetId]
      };

      // If target is on the same domain, call method directly
      if (callSameDomain(targetId, rpc)) {
        return;
      }

      // Attempt to make call via a cross-domain transport.
      var channel = receiverTx[targetId];

      if (!channel) {
        // Not set up yet. Enqueue the rpc for such time as it is.
        if (!earlyRpcQueue[targetId]) {
          earlyRpcQueue[targetId] = [ rpc ];
        } else {
          earlyRpcQueue[targetId].push(rpc);
        }
        return;
      }

      // If we are told to use the legacy format, then we must
      // default to IFPC.
      if (useLegacyProtocol[targetId]) {
        channel = fallbackTransport;
      }

      if (channel.call(targetId, from, rpc) === false) {
        // Fall back to IFPC. This behavior may be removed as IFPC is as well.
        transport = fallbackTransport;
        transport.call(targetId, from, rpc);
      }
    },

    /**
     * Gets the relay URL of a target frame.
     * @param {String} targetId Name of the target frame.
     * @return {String|undefined} Relay URL of the target frame.
     *
     * @member gadgets.rpc
     */
    getRelayUrl: function(targetId) {
      var url = relayUrl[targetId];
      // Some RPC methods (wpm, for one) are unhappy with schemeless URLs.
      if (url && url.indexOf('//') == 0) {
        url = document.location.protocol + url;
      }
      
      return url;
    },

    /**
     * Sets the relay URL of a target frame.
     * @param {String} targetId Name of the target frame.
     * @param {String} url Full relay URL of the target frame.
     * @param {Boolean} opt_useLegacy True if this relay needs the legacy IFPC
     *     wire format.
     *
     * @member gadgets.rpc
     */
    setRelayUrl: function(targetId, url, opt_useLegacy) {
      relayUrl[targetId] = url;
      useLegacyProtocol[targetId] = !!opt_useLegacy;
    },

    /**
     * Sets the auth token of a target frame.
     * @param {String} targetId Name of the target frame.
     * @param {String} token The authentication token to use for all
     *     calls to or from this target id.
     *
     * @member gadgets.rpc
     */
    setAuthToken: function(targetId, token) {
      token = token || "";

      // Coerce token to a String, ensuring that all authToken values
      // are strings. This ensures correct comparison with URL params
      // in the process(rpc) method.
      authToken[targetId] = String(token);

      setupFrame(targetId, token);
    },

    /**
     * Helper method to retrieve the authToken for a given gadget.
     */
    getAuthToken: function(targetId) {
      return authToken[targetId];
    },

    /**
     * Gets the RPC relay mechanism.
     * @return {String} RPC relay mechanism. See above for
     *   a list of supported types.
     *
     * @member gadgets.rpc
     */
    getRelayChannel: function() {
      return transport.getCode();
    },

    /**
     * Receives and processes an RPC request. (Not to be used directly.)
     * Only used by IFPC.
     * @param {Array.<String>} fragment An RPC request fragment encoded as
     *        an array. The first 4 elements are target id, source id & call id,
     *        total packet number, packet id. The last element stores the actual
     *        JSON-encoded and URI escaped packet data.
     *
     * @member gadgets.rpc
     */
    receive: function(fragment) {
      if (fragment.length > 4) {
        // TODO parse fragment[1..3] to merge multi-fragment messages
        process(gadgets.json.parse(
            decodeURIComponent(fragment[fragment.length - 1])));
      }
    },

    /**
     * Receives and processes an RPC request sent via the same domain.
     * (Not to be used directly). Converts the inbound rpc object's
     * Array into a local Array to pass the process() Array test.
     * @param {Object} rpc RPC object containing all request params
     */
    receiveSameDomain: function(rpc) {
      // Pass through to local process method but converting to a local Array
      rpc.a = Array.prototype.slice.call(rpc.a);
      window.setTimeout(function() { process(rpc); }, 0);
    },

    /**
     * Helper method to get the protocol://host:port of an input URL.
     */
    getDomainRoot: getDomainRoot,

    /**
     * Internal-only method used to initialize gadgets.rpc.
     */
    init: function() {
      // Conduct any global setup necessary for the chosen transport.
      // Do so after gadgets.rpc definition to allow transport to access
      // gadgets.rpc methods.
      if (transport.init(process, transportReady) === false) {
        transport = fallbackTransport;
      }
      // Here, we add a hook for the transport to actively set up
      // gadget -> container communication, if we're a gadget.
      if (isGadget && transport.setup('..') === false) {
        transport = fallbackTransport;
      }
    },

    /** Exported constant, for use by transports only. */
    ACK: ACK
  };
}();

// Initialize library/transport.
gadgets.rpc.init();
