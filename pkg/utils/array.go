// Package utils provides utility functions for the public API.

package utils

import (
	"fmt"
	"strings"
)

// Contains checks if a given string is in a given list of strings.
// Returns true if the element was found, false otherwise.
//
// Example:
//
//		list := []string{"a", "b", "c"}
//		element := "b"
//	 contains := Contains(list, element)  // contains is true
func Contains(list []string, element string) bool {
	for _, a := range list {
		if a == element {
			return true
		}
	}
	return false
}

func ContainsPrefix(list []string, element string) bool {
	for _, a := range list {
		if strings.HasPrefix(a, element) {
			return true
		}
	}
	return false
}

// RemoveSimilar removes all elements from the list which contain the given element.
// Returns the filtered list.
//
// Example:
//
//	list := []string{"a", "b", "c"}
//	element := "b"
//	filteredList := RemoveSimilar(list, element)  // filteredList is ["a", "c"]
func RemoveSimilar(list []string, element string) []string {
	filteredArgs := []string{}

	for _, a := range list {
		if !strings.Contains(a, element) {
			filteredArgs = append(filteredArgs, a)
		}
	}

	return filteredArgs
}

// Merge merges two lists of strings and returns the result.
// The result will contain all elements from the first list and all elements from the second list which are not already in the first list.
//
// Example:
//
//	list1 := []string{"a", "b", "c"}
//	list2 := []string{"b", "c", "d"}
//	mergedList := Merge(list1, list2)  // mergedList is ["a", "b", "c", "d"]
func Merge(input1 []string, input2 []string) []string {
	result := make([]string, 0)
	result = append(result, input1...)

	for _, a := range input2 {
		if !Contains(result, a) {
			result = append(result, a)
		}
	}

	return result
}

// Dedupe removes duplicate entries from a given slice.
// Returns a new, deduplicated slice.
//
// Example:
//
//	mySlice := []string{"apple", "banana", "apple", "cherry", "banana", "date"}
//	dedupedSlice := dedupe(mySlice)
//	fmt.Println(dedupedSlice) // Output: [apple banana cherry date]
func Dedupe(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, str := range s {
		if _, ok := seen[str]; !ok {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

// ToKeyValueMap converts a list of strings to a map of strings.
// The input list will be converted based on the delimiter, 'splitBy'.
// The resulting map will contain the keys and values of the input list.
//
// Example:
//
//	list := []string{"a=b", "c=d"}
//	splitBy := "="
//	keyValueMap := ToKeyValueMap(list, splitBy)  // keyValueMap is {"a": "b", "c": "d"}
func ToKeyValueMap(input []string, splitBy string) map[string]string {
	result := make(map[string]string)

	for _, a := range input {
		splittedString := strings.SplitN(a, splitBy, 2)
		if len(splittedString) == 2 {
			key := splittedString[0]
			value := splittedString[1]
			result[key] = value
		}
	}

	return result
}

// ToSlice converts a map of strings to a list of strings.
// The keys and values will be combined by the given delimiter, 'combineBy'.
// The resulting list will contain the keys and values of the input map.
//
// Example:
//
//	map := {"a": "b", "c": "d"}
//	combineBy := "="
//	slice := ToSlice(map, combineBy)  // slice is ["a=b", "c=d"]
func ToSlice(input map[string]string, combineBy string) []string {
	result := []string{}

	for key, value := range input {
		entry := fmt.Sprintf("%s%s%s", key, combineBy, value)
		result = append(result, entry)
	}

	return result
}

// Removes a given key from the input map and uses FindKeyCaseInsensitive() for this. The resulting map is being returned.
// If the key was not found, the input map will be returned.
//
// Example:
//
//	map := {"a": "b", "c": "d"}
//	key := "A"
//	map = Remove(map, key)  // map is {"c": "d"}
func Remove(input map[string]string, key string) map[string]string {
	var found bool
	key, found = FindKeyCaseInsensitive(input, key)
	if found {
		delete(input, key)
	}
	return input
}

// This method tries to find the given key is in the map. It searches different cases of the key:
//
//  1. the exact match
//  2. all lower case letters
//  3. all upper case letters
//
// If the key in any of these versions was found, it'll be returned alongside with a boolean indicating whether or not it was found.
//
// Example:
//
//	map := {"a": "b", "c": "d"}
//	key := "A"
//	key, found = FindKeyCaseInsensitive(map, key)  // key is "a" and found is true
func FindKeyCaseInsensitive(input map[string]string, key string) (string, bool) {
	// look for exact match
	_, found := input[key]

	// look for lower case match
	if !found {
		key = strings.ToLower(key)
		_, found = input[key]
	}

	// look for upper case match
	if !found {
		key = strings.ToUpper(key)
		_, found = input[key]
	}

	return key, found
}

// This method tries to find the given key is in the map and return its value. It searches different cases of the key:
//
//  1. the exact match
//  2. all lower case letters
//  3. all upper case letters
//
// If the key in any of these versions was found, its value will be returned alongside with a boolean indicating whether or not it was found.
//
// Example:
//
//	map := {"a": "b", "c": "d"}
//	key := "A"
//	value, found = FindValueCaseInsensitive(map, key)  // value is "b" and found is true
func FindValueCaseInsensitive(input map[string]string, key string) (string, bool) {
	key, found := FindKeyCaseInsensitive(input, key)
	value := input[key]
	return value, found
}
