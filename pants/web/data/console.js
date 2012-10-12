window.onload = function() {

if ( window.WebSocket === undefined || window.WebSocket === null ) {
    var node = document.querySelector('#console');
    node.parentElement.removeChild(node);
    return;
}

var output = document.querySelector('#output');
var write = function(text) {
    output.innerHTML += (output.innerHTML === '' ? '' : '\n') + text;
}

// The WebSocket

var loc = document.location.host + '/_debug_socket';
loc = ( document.location.protocol === 'http:' ? 'ws://' : 'wss://' ) + loc;

var ws = new WebSocket(loc);

var connected = false;

ws.onopen = function(event) {
    write("<b>[console ready]</b>");
    connected = true;
}

ws.onerror = function(event) {
    if ( ws.readyState === 0 ) {
        write("<b>[unable to connect]</b>");
    } else if ( ws.readyState === 1 ) {
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
        write("<b>[connection closed]</b>");
}

// Input

var input;
var do_input = function() {

input = document.createElement("input");



}

};