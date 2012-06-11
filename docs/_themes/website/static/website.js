$(function(){

var head = $('#heading'),
	focused = false,
	searchbox = $('#search input'),
	search = $('#search a'),
	win = $(window);

var scroll_check = function(event) {
	var scroll = win.scrollTop();
	
	if ( !head.hasClass('at-top') && ( scroll == 0 || focused ) ) {
		head.addClass('at-top');
	} else if ( head.hasClass('at-top') && !focused && scroll > 0 ) {
		head.removeClass('at-top');
	}
};

$(window).scroll(scroll_check);

$('#heading a, #heading input').focus(function() {
	focused = true;
	scroll_check();
}).blur(function() {
	focused = false;
	scroll_check();
});

$('#search input').focus(function() {
	if ( this.value === 'search...' ) {
		this.value = '';
		searchbox.removeClass('blur');
		search.css('opacity', 1);
	}
}).blur(function() {
	if ( this.value === '' ) {
		this.value = 'search...';
		searchbox.addClass('blur');
		search.css('opacity', '');
	}
});

$('#search').submit(function() {
    var inp = $('#search input#q')[0];
    if ( inp.value === 'search...' || inp.value === '' ) {
        alert("You must enter a string to search for.");
        return false;
    }
});

$('#search').removeClass('hidden');

// Do a scroll check.
scroll_check();

});