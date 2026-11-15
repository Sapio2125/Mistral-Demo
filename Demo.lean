def reverseList : List Int → List Int
  | [] => []
  | x :: xs => reverseList xs ++ [x]

theorem reverse_append (xs ys : List Int) :
    reverseList (xs ++ ys) = reverseList ys ++ reverseList xs := by
  induction xs with
  | nil => simp [reverseList]
  | cons x xs ih =>
    simp [reverseList, ih, List.append_assoc]

theorem reverse_reverse_id (xs : List Int) :
    reverseList (reverseList xs) = xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp [reverseList, reverse_append, ih]

#eval reverseList [1, 2, 3, 4]
#eval reverseList (reverseList [1, 2, 3, 4])
