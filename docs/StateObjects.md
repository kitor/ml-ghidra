# `StateObjects.py` and `StateObjectOneShot.py`

Decode and define data structures from CreateStateObject calls.
Create functions where autoanalysis missed them.

Optionally - change name prefixes, set function arg1 to proper name / type and
assign functions to a namespace.

## How to use?

Repository contains two scripts: `StateObjects.py` is meant just for the initial
discovery (it will losely declare state objects from all known references).

`StateObjectOneShot.py` is a more advanced script that works on a single
`CreateStateObject` call and allows for more fine tuned definition with custom
prefixes, namespaces and setting function calls arg1 to a proper data type.

## Prerequisites

You have to find and create `CreateStateObject` function first. It has to
have properly-ish declared signature. For example:

```
StateObject *
CreateStateObject(char *name, uint32_t initialState, StateObjEntry *entryList,
                 uint32_t inputs, uint32_t states)
```

If your project doesn't (yet) have `StateObject` or `StateObjEntry` types, it
is sufficient to replace them with `void` type like this:

```
void *
CreateStateObject(char *name, uint32_t initialState, void *entryList,
                 uint32_t inputs, uint32_t states)
```

After function declaration is properly set, use "Commits param/return"
functionality from right-click menu in Decompile window.

Running either of scripts will auto-create `StateObjEntry` and `StateObjEntry *`
data types if those are missing.

## Limitiations

At the time of writing, scripts will fail to create new functions in some
conditions, eg. when at function address there's already something (wrongly)
defined as a data type.

There are also cases (examples being `DisplayStateWithImgMute` and `DisplayState`
on pre-DIGIC 6 models) where multiple state objects share the same function table
or some function calls. When running automatic state objects creation this will
result in multiple name prefixes being applied (in order those were discovered).

If you find such a case, you can quickly fix that via single shot script.

## Automatic state objects creation via `StateObjects.py`

`StateObjects.py` will follow all x-refs to `CreateStateObject` in attempt
to define date structures and follow those to discover missing functions.

**It is meant to be run only once, ideally after initial project analysis is
done, and all the extra stubs defined.**

To use: In either Listing or Decompile window, go to a location inside
`CreateStateObject` function. Go to plugins window, run `StateObjects.py`.

Plugin will follow all x-refs, try to decode each call arguments, and where
possible:

* Fetch state object name from 1st arg if available (`StateObj_$addr` fallback)
* Create data structure `StateObjEntry[inputs][states]` at address from 3rd arg
* Decode all entries from that data structure to receive function pointers
* If any address is not already declared as a function, attempt to create one
* Rename function at every listed address by replacing prefix `FUN_` with
   state object name

**Please note that depending on camera / ROM there may be one or more thunk
functions for `CreateStateObject`, in such a case you want to run this script
once for each thunk to discover more state objects.**

## Manual, single shot state object creation/update via `StateObjectOneShot.py`

The proposed `StateObjectOneShot.py` use is by assigning it to a hot key, but
can be executed from Script Manager as well.

First, find a `CreateStateObject` function **call**. For example:

```
# In decompiler:
DAT_12345 = CreateStateObject("SomeState",0,(StateObjEntry *)0xDEADBEEF, 5, 2);
# or in Listing:
bl CreateStateObject
```

When call is highlighted, press assigned hotkey or execute script from Script Manager.

A window will pop up, allowing you to set following parameters:
* Function prefix (defaults to state object name)
* Old prefix (opt., to be substituted instead of default `FUN_` prefix, eg. if you may have changed it earlier)
* Namespace (opt., enter name of *existing* namespace you want to assign functions to)
* Arg1 data type (opt., will replace 1st arg data type with selected one)
* Arg1 name (opt., works only with Arg1 datat type - rename arg1 to following string)

`Arg1` handling is useful since all StateObject operate using `TaskClass` task.
Every function executed receive pointer to a data structure at argument 1.
This will propagate data types down through the state object function chain.

While going on into details of `TaskClass` is beyond scope of this document;
in most cases you will find a data structure created just before
`CreateStateObject` call.

Result of such call is saved to some early field of this structure.
The structure is very likely the data structure that also gets passed into Arg1
of state change function calls.

