/*
 * To run this, you'll need NodeJS installed. Go to http://nodejs.org to
 * install it. Then run the command:
 *
 *      node app.js
 *
 * This server will preload `blockLimit` number of blocks and spit them out
 * whenever someone loads the main URL and then generate another block. It uses
 * Node's built-in event loop to handle events asynchronously.
 *
 */

var http = require('http'),
    events = require('events'),
    alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    base = alpha.length,
    blocks = [],
    Generator = function () {
        // String we are on, in reverse
        this.current = [0];
    },

    /*
     *
     * Configuration
     *
     */

    // Number of blocks to generate beforehand
    blockLimit = 400,

    // 50,000,000 in base-52, in reverse
    blockSize = [24, 6, 31, 43, 6]

    // Time to wait between generating a new block
    t = 20;

Generator.prototype = new events.EventEmitter;

/*
 * Takes an array where the first index is the first character and so on, and
 * turns it into a string of characters a-Z.
 */
Generator.prototype.toString = function (a) {
    var s, i;

    // Iterate starting at the end and add each new character to the string
    for(s = '', i = a.length; i >= 0; i--) {
        s += alpha.charAt(a[i]);
    }

    return s;
};


/*
 * The function to run on a new 'next' event.
 */
Generator.prototype.next = function () {
    var root = this,
        interval;

    // Called every t milliseconds to generate a new block
    interval = setInterval(function () {
        var i, x, carry = 0;

        // Stop the generation if we are at the limit
        if (blocks.length == blockLimit) {
            clearInterval(interval);
            return;
        }

        // Increment the Ascii by adding the blockSize array to the
        // root.current array. Carries values when needed.
        for (i = 0; i < blockSize.length || carry != 0; i++) {
            if (i >= root.current.length) {
                root.current[i] = 0;
            }

            x = root.current[i] + carry + ((i < blockSize.length) ? blockSize[i] : 0);

            if (x > base) {
                root.current[i] = x % base;
                carry = Math.floor(x / base);
            } else {
                root.current[i] = x;
                carry = 0;
            }
        }

        var s = root.toString(root.current);
        console.log('Generated new block: ' + s);
        blocks.push(s);
    }, t);
};

// Setup event handler for next event
var gen = new Generator();
gen.on('next', gen.next);

http.createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(blocks.pop());

    // Trigger next generation
    gen.emit('next');
}).listen(8000);

console.log('Starting server...');

// Start the first generation
gen.emit('next');
