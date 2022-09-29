pub(crate) trait prog_type {
    fn prog_run(&self, ctx: *const ()) -> u32;
}

fn entry<PT>(prog: &PT, ctx: *const ()) -> u32
where
    PT: prog_type,
{
    prog.prog_run(ctx)
}
