import PyQt5.QtCore
import PyQt5.QtGui
import PyQt5.QtWidgets

import idaapi
import idautils

from operator import itemgetter


class FunctionWalker():
  def countCallInstructions(self, ea):
    count = 0
    func = idaapi.get_func(ea)
    flowchart = idaapi.FlowChart(func)

    for bb in flowchart:
      ea = bb.start_ea
      while ea < bb.end_ea:
        instr = idautils.DecodeInstruction(ea)
        if instr.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
          count +=1
        ea = idaapi.next_head(instr.ea, bb.end_ea)
    return count


class ExportTableModel(PyQt5.QtCore.QAbstractTableModel):
  def __init__(self, data):
    super(ExportTableModel, self).__init__()
    self._data = data
    self.columns = ["Name", "Address", "Ordinal", "Is Code", "Starting Mnem", "Call Count", "Basic Blocks Count", "Function Size"]

  def data(self, index, role):
    if role == PyQt5.QtCore.Qt.DisplayRole:
      return self._data[index.row()][index.column()]

  def headerData(self, section, orientation, role):
    if role == PyQt5.QtCore.Qt.DisplayRole:
      if orientation == PyQt5.QtCore.Qt.Horizontal:
          return self.columns[section]

  def rowCount(self, index):
    return len(self._data)

  def columnCount(self, index):
    return len(self._data[0])


class ExportListUI(idaapi.PluginForm):
  def GetExportData(self):
    fw = FunctionWalker()
    data = []
    for _, ordinal, ea, name in idautils.Entries():
      iscode = idaapi.is_code(idaapi.get_flags(ea))
      if iscode:
        func = idaapi.get_func(ea)
        flowchart = idaapi.FlowChart(func)
        func_size = func.size()
        bb_count = len(list(flowchart))
        call_count = fw.countCallInstructions(ea)
      else:
        func_size = 'NA'
        bb_count = 'NA'
        call_count = 'NA'

      if ordinal == ea:
        ordi = "[main entry]"
      else:
        ordi = ordinal

      data.append([name, hex(ea), ordi, str(iscode), idaapi.print_insn_mnem(ea), call_count, bb_count, func_size])
    return data

  def ActionCellDoubleClicked(self, item):
    idx = self.model.columns.index("Address")
    ea_item = item.siblingAtColumn(idx)
    ea = self.proxymodel.data(ea_item)
    idaapi.jumpto(int(ea,16))

  def ActionFilterClosedClicked(self, checked):
    self.filterWidget.setVisible(False)

  def ActionAutoFilterToggled(self, checked):
    if checked:
      self.isCodeFilterModel.setFilterRegularExpression(PyQt5.QtCore.QRegularExpression("[^False]", PyQt5.QtCore.QRegularExpression.CaseInsensitiveOption))
      self.noRetnFilterModel.setFilterRegularExpression(PyQt5.QtCore.QRegularExpression("[^retn]", PyQt5.QtCore.QRegularExpression.CaseInsensitiveOption))
    else:
      self.isCodeFilterModel.setFilterRegularExpression(PyQt5.QtCore.QRegularExpression(".*", PyQt5.QtCore.QRegularExpression.CaseInsensitiveOption))
      self.noRetnFilterModel.setFilterRegularExpression(PyQt5.QtCore.QRegularExpression(".*", PyQt5.QtCore.QRegularExpression.CaseInsensitiveOption))


  def ActionShowFilter(self):
    self.filterWidget.setVisible(True)
    self.filterText.setFocus()

  def ActionTextFilter(self, text):
    self.proxymodel.setFilterRegularExpression(PyQt5.QtCore.QRegularExpression(text, PyQt5.QtCore.QRegularExpression.CaseInsensitiveOption | PyQt5.QtCore.QRegularExpression.MultilineOption))

  def OnCreate(self, form):
    self.parent = self.FormToPyQtWidget(form)
    self.layout = PyQt5.QtWidgets.QVBoxLayout()

    self.filterWidget = PyQt5.QtWidgets.QWidget()
    self.filterWidget.setVisible(False)
    self.filterlayout = PyQt5.QtWidgets.QHBoxLayout(self.filterWidget)
    self.filterText = PyQt5.QtWidgets.QLineEdit()
    self.filterText.textChanged.connect(self.ActionTextFilter)
    self.closeButton = PyQt5.QtWidgets.QPushButton("X")
    self.closeButton.setStyleSheet("color:rgb(93, 173, 226);font-weight: 900;")
    self.closeButton.setFixedSize(PyQt5.QtCore.QSize(25, 25))
    self.closeButton.clicked.connect(self.ActionFilterClosedClicked)
    self.closeButton.setToolTip("Close filter")
    self.autoFilterCheckbox = PyQt5.QtWidgets.QCheckBox("Auto Filter")
    self.autoFilterCheckbox.setToolTip("Removes:\n- `retn` from `Starting Mnem`\n- `False` from `Is Code`")
    self.autoFilterCheckbox.toggled.connect(self.ActionAutoFilterToggled)
    self.filterlayout.addWidget(self.closeButton)
    self.filterlayout.addWidget(self.autoFilterCheckbox)
    self.filterlayout.addWidget(self.filterText)

    self.ctr_f_shortcut = PyQt5.QtWidgets.QShortcut(PyQt5.QtGui.QKeySequence(PyQt5.QtCore.Qt.CTRL + PyQt5.QtCore.Qt.Key_F), self.parent, activated=self.ActionShowFilter)

    self.table = PyQt5.QtWidgets.QTableView()
    self.table.sortByColumn(0, PyQt5.QtCore.Qt.AscendingOrder)
    self.table.setSelectionBehavior(PyQt5.QtWidgets.QAbstractItemView.SelectRows)
    #self.table.setAlternatingRowColors(True)
    self.layout.addWidget(self.table)
    self.layout.addWidget(self.filterWidget)
    self.parent.setLayout(self.layout)

    self.model = ExportTableModel(self.GetExportData())
    self.proxymodel = PyQt5.QtCore.QSortFilterProxyModel()
    ## Region: This is for the Auto Filter Toggle
    self.isCodeFilterModel = PyQt5.QtCore.QSortFilterProxyModel()
    self.isCodeFilterModel.setSourceModel(self.model)
    self.isCodeFilterModel.setFilterKeyColumn(self.model.columns.index("Is Code"))
    self.noRetnFilterModel = PyQt5.QtCore.QSortFilterProxyModel()
    self.noRetnFilterModel.setSourceModel(self.isCodeFilterModel)
    self.noRetnFilterModel.setFilterKeyColumn(self.model.columns.index("Starting Mnem"))
    ## End Region
    self.proxymodel.setSourceModel(self.noRetnFilterModel)
    self.proxymodel.setFilterKeyColumn(-1)
    self.table.setModel(self.proxymodel)
    self.table.doubleClicked.connect(self.ActionCellDoubleClicked)
    self.table.activated.connect(self.ActionCellDoubleClicked)
    self.table.setSortingEnabled(True)

    self.table.setVisible(False)
    self.table.resizeColumnsToContents()
    self.table.horizontalHeader().setStretchLastSection(True)
    self.table.setShowGrid(False)
    self.table.setVisible(True)

  def Show(self, caption, options=0):
    super().Show(caption, options)

  def OnClose(self, form):
    pass

