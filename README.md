# tracer_module
This is a custom linux kernel module that can be used to trace system calls. The module is located under the module folder. A simple test file is located under the tests folder

## module
The module uses kprobes to trace system calls. A device driver is included with the module. This is used to register specific processes 
with the module. The module only tracks processes that are registered with the module. The module currently only places kprobes on the first three
syscalls in the syscall table on your system. This can be edited by changing the NUM_SYSCALLS macro in /module/tracer.c.

To run the module do the following under the module directory:
<pre><code>make
sudo insmod tracer.ko
</code></pre>

To verify if the module has been correctly inserted do:
<pre><code>sudo lsmod | grep tracer
</code></pre>
This should show the module/modules with the name tracer in them

To remove the module simply do:
<pre><code>sudo rmmod tracer.ko
</code></pre>

## tests
This directory contains a basic test that opens the device driver and registers a process with the module by using IOCTL. 
The test then requires the user to input a number (this is all to showcase how the linux kernel module captures sytem calls).
The test then closes the device and proceeds to exit the program. To compile the test use:
<pre><code>make
</code></pre>
under the tests folder.

To run the test use:
<pre><code>sudo ./test
</code></pre>

Make sure the module is inserted before running the test otherwise the test will fail to open the device driver
