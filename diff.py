#!/usr/bin/env python
import argparse

from nffg import NFFGToolBox, NFFG


def _calculate_diffs (old_path, new_path):
  """
  Calculate and print the difference of the two :any:`NFFG` given by it"s path.

  :param old_path: file path of the original :any:`NFFG`
  :param new_path: file path of the modified :any:`NFFG`
  :return: None
  """
  print "Calculate the difference NFFGs..."
  old = NFFG.parse_from_file(old_path)
  NFFGToolBox.recreate_all_sghops(nffg=old)
  new = NFFG.parse_from_file(new_path)
  NFFGToolBox.recreate_all_sghops(nffg=new)
  add_nffg, del_nffg = NFFGToolBox.generate_difference_of_nffgs(old=old,
                                   new=new, ignore_infras=True)
  print "\nADD NFFG:"
  print add_nffg.dump()
  print "\nDEL NFFG:"
  print del_nffg.dump()


if __name__ == "__main__":
  # Implement parser options
  parser = argparse.ArgumentParser(description="Calculate differences of NFFGs",
                                   add_help=True)
  parser.add_argument("old", action="store", type=str, help="path for old NFFG")
  parser.add_argument("new", action="store", type=str, help="path for new NFFG")
  # Parsing arguments
  args = parser.parse_args()
  _calculate_diffs(old_path=args.old, new_path=args.new)
