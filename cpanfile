requires "Getopt::Long", "2.54";
requires "Mojo::JSON";
requires "Mojo::UserAgent";

on 'test' => sub {
    requires "Test::More";
    requires "Test::Exception";
    requires "Test::MockObject";
    requires "Test::Output";
    requires "Capture::Tiny";
};
