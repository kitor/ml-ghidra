# Populates StateObject, one shot variant
#
# Bind to a key. Select `CreateStateObject` call in Decompile
# (or branch in Listing). Press a key, magic will happen.
#
# @category MagicLantern

from mlLib.stateObjects import *

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.data import DataType
from ghidra.program.model.data import DataTypeManager
from ghidra.util.data.DataTypeParser import AllowedDataTypes

from docking import DialogComponentProvider, DockingWindowManager
from docking.options.editor import OptionsEditorPanel, StringEditor
from javax.swing import *
from java.awt import GridLayout

class StateObjectDialog(DialogComponentProvider):
    def __init__(self, name, addr, states, inputs):
        self._success = False

        self.prefix = JTextField(name)
        self.oldPrefix = JTextField("")

        #self.nsname = JLabel("not set")
        self.nsname = JTextField("")
        self.dtname = JLabel("not set")
        self.argName = JTextField("pObj")
        self.nsbutton = JButton("Select namespace")
        self.dtbutton = JButton("Select data type")
        self.nsreset = JButton("Reset namespace")
        self.dtreset = JButton("Reset data type")

        self.nsbutton.addActionListener(self._nsbutton_click)
        self.dtbutton.addActionListener(self._dtbutton_click)
        self.nsreset.addActionListener(self._nsreset_click)
        self.dtreset.addActionListener(self._dtreset_click)

        self.dataType = None
        self.namespace = None

        super(StateObjectDialog, self).__init__("StateObject decoder")
        options = []
        panel = JPanel(GridLayout(0,2))

        # Info block
        panel.add(JLabel("StateObject name"))
        panel.add(JLabel(name))
        panel.add(JLabel("StateObject config"))
        panel.add(JLabel(addr))
        panel.add(JLabel("States"))
        panel.add(JLabel(states))
        panel.add(JLabel("Inputs"))
        panel.add(JLabel(inputs))

        # Editable config
        panel.add(JLabel("Function prefix"))
        panel.add(self.prefix)
        panel.add(JLabel("Old prefix"))
        panel.add(self.oldPrefix)
        panel.add(JLabel("Namespace"))
        panel.add(self.nsname)
        panel.add(JLabel("Arg1 Data type"))
        panel.add(self.dtname)
        panel.add(JLabel("Arg1 name"))
        panel.add(self.argName)

        # Buttons
        panel.add(self.nsbutton)
        panel.add(self.dtbutton)
        panel.add(self.nsreset)
        panel.add(self.dtreset)

        self.addOKButton()
        self.addCancelButton()
        self.addWorkPanel(panel)

    def okCallback(self):
        self._success = True
        self.close()

    def cancelCallback(self):
        self._success = False
        self.close()

    def _dtbutton_click(self, event):
        tool = state.getTool()
        dtm = currentProgram.getDataTypeManager()
        selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
        tool.showDialog(selectionDialog)
        self.dataType = selectionDialog.getUserChosenDataType()

        self.dtname.setText(str(self.dataType))

    def _nsbutton_click(self, event):
        # TODO: how to do a namespace selection dialog?
        # I can't get any function to list all namespaces...
        pass

    def _nsreset_click(self, event):
        self.nsname.setText("None")
        self.namespace = None

    def _dtreset_click(self, event):
        self.dtname.setText("None")
        self.dataType = None

    def getUserInputs(self):
        return [ self.prefix.getText(),
                self.oldPrefix.getText(),
                self.nsname.getText(),
                self.dataType,
                self.argName.getText() ]

    def getStatus(self):
        return self._success

    @staticmethod
    def main(args):
        print("main")

entry = getStateObjectArgs(currentAddress)
if not entry:
    print("Unable to decode CreateStateObject args")
    exit(1)

name, struct, inputs, states = entry

tool = state.getTool()
offString = format(struct.getOffset(), "08X")
dialog = StateObjectDialog(name, offString, str(inputs), str(states))
tool.showDialog(dialog)

if not dialog.getStatus():
    # user cancelled or closed the dialog other way than "OK"
    exit(0);

prefix, oldPrefix, nsname, dataType, argName = dialog.getUserInputs()

StateObjectEntryType = CreateStateObjectEntryDataType()

pointers = getStateChangeFunctions(
         addr = struct,
         inputs = inputs,
         states = states )

setStateObjectConfigDataType(StateObjectEntryType, struct, inputs, states)

setStateChangeFnSignatures(
        pointers = pointers,
        prefix = prefix,
        oldPrefix = oldPrefix,
        namespace = getNamespacesByName(currentProgram, None, nsname)[0],
        datatype = dataType,
        argName = argName )

