from mlLib.toolbox import *
from mlLib.MemTable import *

categories = []

def createProgramTree(treeBase, memTable, program = None):
    if not isinstance(memTable, MemTable):
        print("memTable is not MemTable object!")

    if program is None:
        from __main__ import currentProgram
        program = currentProgram

    listing = program.getListing()

    # create tree name
    treeName = treeBase
    suffix = 0
    while listing.getRootModule(treeName):
        suffix += 1
        treeName = "{}_{}".format(treeBase, suffix)
    root = listing.createRootModule(treeName)

    for r in memTable:
        if r.module:
            print(r.module)
            # try to create a category if it DNE
            submodules = r.module.split("/")

            # recursivly create module tree
            parentModule = root
            for name in submodules:

                # deal with memory region name and module name conflict
                regionName = name
                while listing.getFragment(treeName, regionName):
                    regionName += "_"

                # deal with module name region conflicts
                while True:
                    tmp = listing.getModule(treeName, regionName)
                    if not tmp or parentModule.contains(tmp):
                        break
                    regionName += "_"

                module = listing.getModule(treeName, regionName)
                if not module:
                    parentModule = parentModule.createModule(regionName)
                else:
                    parentModule = module

            # add fragment
            region = listing.getFragment(treeName, r.name)
            if region and root.contains(region):
                # move from root to submodule
                parentModule.reparent(r.name, root)
