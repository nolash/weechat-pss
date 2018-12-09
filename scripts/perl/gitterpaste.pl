weechat::register(
	"gitterpaste",
	"lash",
	"0.3.0",
	"GPLv3",
	"renders content in xclip clipboard selection to a gitter channel in format suitable for code display",
	"gtc_shutdown",
	"");

our $gtc_hook = weechat::hook_command(
	"gtc",
	"paste code to gitter",
	"",
	"",
	"takes no arguments",
	"gtc_cb",
	"",
);

sub gtc_paste_cb {
	($data, $cmd, $ret, $out, $err) = @_;

	if ($ret == weechat::WEECHAT_HOOK_PROCESS_ERROR) {
		weechat::print("", "gitter code paste error (" . $ret . "): " . $err);
		return weechat::WEECHAT_RC_ERROR;
	} else {
		$out =~ s/\n/\\x0d/smg;
		weechat::command(weechat::current_buffer(), '/input insert ```\x0d' . $out . '\x0d```\x0a');
	}
	return weechat::WEECHAT_RC_OK;
}

sub gtc_cb {
	($data, $buf, $args) = @_;

	my $bufname = weechat::buffer_get_string($buf, "full_name");
	if ($bufname !~ /\.gitter\.#/) {
		weechat::print("", "buffer " . $bufname . " is not a gitter.im buffer");
		return weechat::WEECHAT_RC_ERROR;
	}
	weechat::hook_process("xclip -selection clipboard -o", 2000, "gtc_paste_cb", "");
	return weechat::WEECHAT_RC_OK;
}

sub gtc_shutdown {
	weechat::unhook($gtc_hook);
}
