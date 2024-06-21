/// Generate an enum to be used as an error type.
///
/// This will automatically generate the enum, but also implement `Display` with given format
/// strings and optionally indicate the source error for errors which wrap another error.
///
/// Example usage:
/// ```ignore
/// make_error_type!(pub enum MyError {
///     Unknown; "Unknown error",
///     IncorrectLength(length: usize); "Incorrect length {length}, expected 123",
///     InvalidHexData(source: hex::FromHexError); "Cannot convert hex string: {source}"; source,
/// });
/// ```
macro_rules! make_error_type {
    (@fmt_source) => { None };
    (@fmt_source $sourcen:expr) => { Some($sourcen) };

    (
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident {
            $( $(
                #[$tattr:meta] )*
                $tname:ident
                    $(( $( $( #[$t_tuple_arg_attr:meta] )* $t_tuple_arg_name:ident : $t_tuple_arg_ty:ty),+ $(,)? ))?
                    $({ $( $( #[$t_struct_arg_attr:meta] )* $t_struct_arg_name:ident : $t_struct_arg_ty:ty),+ $(,)? })?
                ; $tmsg:literal $(( $($tmsgarg:expr),* ))?
                $( ; $sourcen:expr )?
            ),+ $(,)?
        }
    ) => {
        $( #[$attr] )*
        #[derive(::std::fmt::Debug)]
        $vis enum $name {
            $(
                $( #[$tattr] )*
                $tname
                    $(( $( $( #[$t_tuple_arg_attr] )* $t_tuple_arg_ty),+ ))?
                    $({ $( $( #[$t_struct_arg_attr] )* $t_struct_arg_name : $t_struct_arg_ty),+ })?
            ),+
        }

        impl std::error::Error for $name {
            #[allow(unused_variables)]
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        Self::$tname
                            $(( $($t_tuple_arg_name),+ ))?
                            $({ $($t_struct_arg_name),+ })?
                        =>
                        make_error_type!(@fmt_source $($sourcen)?)
                    ),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $(
                        Self::$tname
                            $(( $($t_tuple_arg_name),+ ))?
                            $({ $($t_struct_arg_name),+ })?
                        =>
                        write!(_f, $tmsg $($(, $tmsgarg)*)? )
                    ),+
                }
            }
        }
    };
}
