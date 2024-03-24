## Author: @xorhex
## Copyright: 2024

__author__ = "@xorhex"

import idaapi
import idautils
import idc

from idaextras.Logger import Logger
from idaextras.IDAExtrasListExportsForm import ExportListUI

import PyQt5.QtCore
import PyQt5.QtGui
import PyQt5.QtWidgets

ACTION_NAME_IDA_EXTRAS = "idaextras"

logger = Logger()


## Custom Export Window

CUSTOM_EXPORT_WINDOW_DISPLAY_NAME = f"exports"
CUSTOM_EXPORT_WINDOW = f"{ACTION_NAME_IDA_EXTRAS}:{CUSTOM_EXPORT_WINDOW_DISPLAY_NAME}"

class ExportsDisplay(idaapi.action_handler_t):
  def __init__(self):
    idaapi.action_handler_t.__init__(self)
    self.exports = ExportListUI()

  def activate(self, ctx):
      self.exports.Show(f"IDA Extras: {CUSTOM_EXPORT_WINDOW_DISPLAY_NAME.title()}")

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

if idaapi.register_action(idaapi.action_desc_t(
  CUSTOM_EXPORT_WINDOW,
  CUSTOM_EXPORT_WINDOW_DISPLAY_NAME.title(),
  ExportsDisplay(),
  "Ctrl-Alt-E")):
  idaapi.attach_action_to_menu("View/IDA Extras/", CUSTOM_EXPORT_WINDOW, idaapi.SETMENU_APP)
  logger.log(CUSTOM_EXPORT_WINDOW, "register_action", "Attached")
else:
  idaapi.unregister_action(CUSTOM_EXPORT_WINDOW)



class context_handler_copy_bytes(idaapi.action_handler_t):
  def __init__(self):
    super().__init__()

  def activate(self, ctx):
    ea = idc.read_selection_start()
    bites = []
    
    instr_bites = idaapi.get_bytes(ea, idc.read_selection_end() - idc.read_selection_start())
    for b in instr_bites:
      bites.append(f'{b:02x}')

    cb = PyQt5.QtWidgets.QApplication.instance().clipboard()
    cb.clear(mode = cb.Clipboard)
    cb.setText(f'{" ".join(bites)}', mode=cb.Clipboard)


  def update(self, ctx):
    return super().update(ctx)

class ContextHooks(idaapi.UI_Hooks):
  def finish_populating_widget_popup(self, form, popup) -> None:
    if idaapi.get_widget_type(form) in [idaapi.BWN_DISASM, idaapi.BWN_DUMP]:
      if idc.read_selection_start() != idaapi.BADADDR and idc.read_selection_end() != idaapi.BADADDR:
        action_copy_bytes = idaapi.action_desc_t(None, f"Copy Bytes", context_handler_copy_bytes())
        idaapi.attach_dynamic_action_to_popup(form, popup, action_copy_bytes, None, idaapi.SETMENU_FIRST)


hooks = ContextHooks()
hooks.hook()
