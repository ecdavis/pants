window.onload = function() {

if ( window.WebSocket === undefined || window.WebSocket === null )
    return;

var node = document.querySelector('#console');

// Add the header.
var head = document.createElement('h2');
head.textContent = 'Console';
node.appendChild(head);

// Create the output pane.
var output = document.createElement('pre');
node.appendChild(output);

var write = function(text) {
    output.innerHTML += (output.innerHTML === '' ? '' : '\n') + text;
}

// TODO: The Input Element

// The WebSocket
var loc = (document.location.protocol === 'http:' ? 'ws://' : 'wss://') +
           document.location.host + '/_debug_socket';

var ws = new WebSocket(loc),
    connected = false;

ws.onopen = function(event) {
    write("<b>[console ready]</b>");
    connected = true;
}

ws.onerror = function(event) {
    if ( ws.readyState === 0 ) {
        write("<b>[unable to connect]</b>");
    } else {
        write("<b>[connection closed]</b>");
        connected = false;
        ws.close();
    }
}

ws.onmessage = function(event) {
    write(event.data);
}

ws.onclose = function(event) {
    if ( connected )
        write("<b>[connection closed]</b>")
    connected = false;
}

};