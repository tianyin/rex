ENTRY(bpf_main);

PHDRS { text PT_LOAD ; }
SECTIONS
{
  . = 0x0;
  .text : { *(.text) } : text
  .data : { *(.data) } 
  .bss : { *(.bss) }
}
