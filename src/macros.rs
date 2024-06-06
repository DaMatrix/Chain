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
    (@fmt_args $tname:ident) => { Self::$tname };
    (@fmt_args $tname:ident ( $($targn:ident),+ )) => { Self::$tname($($targn),+) };

    (@fmt_source) => { None };
    (@fmt_source $sourcen:expr) => { Some($sourcen) };

    (
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident {
            $( $(
                #[$tattr:meta] )*
                $tname:ident $(( $($targn:ident : $targ:ty),+ ))?
                ; $tmsg:literal
                $( ; $sourcen:expr )?
            ),+ $(,)?
        }
    ) => {
        $( #[$attr] )*
        #[derive(::std::fmt::Debug)]
        $vis enum $name {
            $(
                $( #[$tattr] )*
                $tname $(( $($targ),+ ))?
            ),+
        }

        impl std::error::Error for $name {
            #[allow(unused_variables)]
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        make_error_type!(@fmt_args $tname $(( $($targn),+ ))?)
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
                        make_error_type!(@fmt_args $tname $(( $($targn),+ ))?)
                        =>
                        write!(_f, $tmsg)
                    ),+
                }
            }
        }
    };
}

/// Generate an enum where each variant simply wraps a numeric ordinal number.
///
/// This will automatically generate the enum, but also implement the following traits:
/// * `ToOrdinal` and `FromOrdinal` with the given ordinal numbers
/// * `ToName` and `FromName` with the variant names
/// * `Display` with the variant names
///
/// Additionally, a constant array containing every enum variant will be generated with the
/// given name and visibility.
///
/// Example usage:
/// ```ignore
/// make_ordinal_enum!(pub enum MyError {
///     Hello = 2,
///     World = 3,
/// }
/// all_variants=pub(crate) ALL_VARIANTS);
/// ```
macro_rules! make_ordinal_enum {
    (
        $( #[$eattr:meta] )*
        $evis:vis enum $ename:ident {
            $(
                $( #[$vattr:meta] )*
                $vname:ident = $vord:literal,
            )+
        }
        all_variants=$all_variants_vis:vis $all_variants:ident
    ) => {
        $( #[$eattr] )*
        $evis enum $ename {
            $( $( #[$vattr] )* $vname = $vord, )+
        }

        impl $ename {
            $all_variants_vis const $all_variants : &'static [Self] =
                &[ $( Self::$vname, )+ ];
        }

        impl crate::utils::ToOrdinal for $ename {
            fn to_ordinal(&self) -> u32 {
                match self {
                    $( Self::$vname => $vord, )+
                }
            }
        }

        impl crate::utils::FromOrdinal for $ename {
            const ALL_ORDINALS: &'static [u32] = &[ $($vord,)+ ];

            fn from_ordinal(ordinal: u32) -> Result<Self, u32> {
                match ordinal {
                    $( $vord => Ok(Self::$vname), )+
                    _ => Err(ordinal),
                }
            }
        }

        impl crate::utils::ToName for $ename {
            fn to_name(&self) -> &'static str {
                match self {
                    $( Self::$vname => stringify!($vname), )+
                }
            }
        }

        impl crate::utils::FromName for $ename {
            const ALL_NAMES: &'static [&'static str] = &[ $(stringify!($vname),)+ ];

            fn from_name(name: &str) -> Result<Self, &str> {
                match name {
                    $( stringify!($vname) => Ok(Self::$vname), )+
                    _ => Err(name),
                }
            }
        }

        impl std::fmt::Display for $ename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(crate::utils::ToName::to_name(self))
            }
        }
    };
}
