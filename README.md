# UP-Stackoverflow

## Preface
This repository explains and provides a fix for a stack overflow bug inside UnityPlayer. This code is valid for version **2019.4.31**, I am unsure if this has been patched in later versions of Unity, if not, this would still be applicable. The overflow itself occurs inside the **Transform::CountNodesDeep()** function. This method counts all the children of a transform, all the children of those children, so on and so fourth, until coming to a final result, which is then returned to the caller. Neat. A popular avatar crasher inside VRChat known as AA-12 exploits this function by setting the right toe's child back to the ankle. See where I'm getting at? When **CountNodesDeep()** gets called on the ankle's transform, it will begin to count the toe's children, when counting the toe's children, since the ankle is a child of the toe, it will begin counting the ankle's children... again. This causes infinte loop that never ends, hence the name "stack overflow". (ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->ankle->toe->forever)

## So, how do we fix this?
It's relatively straight forward actually. When debugging the crash initially in IDA, I noticed when the function went back to count the ankle again, the ankle's pointer remained the same... obviously. All you need to do to implement a fix is detour the original **Transform::CountNodesDeep()** function with your own implementation of it that checks to see if an object's pointer has already been seen in the current pass through of the function.

Here's what IDA's pseudocode of the function looks like:
![ida screenshot](https://i.invalid.gg/ida64_uMcFOP0QUY.png)

## Fix
It's really fucking easy, actually. Write a detour, then call the custom implementation with an empty vector.
### New (Updated 2-9-2022)
The original anti works fine, however when reading a transform with **tons** of children, it can take an incredibly long time. This is due to vectors being relatively slow to find data when the container is massive. I've fixed this by using an unordered_set instead, which is C++'s version of a hashset, allowing for faster, constant, lookup speeds.
```c
std::uint32_t patches::transform_count_nodes_deep(std::uintptr_t* _this)
{
    static auto genuine_f = get().fetch_patch(xorstr_("CountNodesDeep")).detour.get_original<decltype(&transform_count_nodes_deep)>();
    
    std::unordered_set<std::uintptr_t*> v = {};
    return transform_count_nodes_deep_detour(_this, v);
}

std::uint32_t patches::transform_count_nodes_deep_detour(std::uintptr_t* _this, std::unordered_set<std::uintptr_t*>& map)
{
   std::uint32_t v3 = 1;
    
    if (_this == nullptr) // check if this is null
        return v3;

    if (map.contains(_this)) // check if our hashset already contains _this
    {
        *(_this + 16) = 0; // found it, set children of ankle to 0
        return 0; // return 0 so our fix can pick it up
    }
    
    map.insert(_this); // first time seeing the transform, let's add it to the hashset
    
    if ( *(_this + 16) ) // total children in transform
    {
        std::int32_t v1 = 0;
        std::int64_t v4 = 0;
        do
        {
            const std::uint32_t v5 = transform_count_nodes_deep_detour(*reinterpret_cast<std::uintptr_t**>(v4 + *(_this + 14)), map); // get next child in queue
            if (v5 == 0) // flag was triggered
            {
                *(_this + 16) = 0; // set children of toe to 0
                return v3; // return already counted transforms
            }
            ++v1; // child_increment
            v4 += 8; // child queue increment
            v3 += v5; // increment total transforms found
        }
        while ( static_cast<std::uint64_t>(v1) < *(_this + 16) ); // while child_increment < total children in transform
    }
    return v3;
}
```

### Old
```cpp
uint32_t detours::transform_count_nodes_deep_detour(int64_t* _this, std::vector<int64_t*>& map)
{
	uint32_t v3 = 1;

	if (_this == nullptr) return v3; // check if this is null
	if (std::ranges::find(map, _this) != map.end()) // check if our vector already contains _this
	{
		*(reinterpret_cast<uint64_t*>(_this) + 16) = 0; // found it, set children of ankle to 0
		return 0; // return 0 so our fix can pick it up
	}
	map.push_back(_this); // first time seeing the transform, let's add it to the vector
	if (*(reinterpret_cast<uint64_t*>(_this) + 16)) // total children in transform
	{
		int32_t v1 = 0;
		int64_t v4 = 0;
		do
		{
			const auto next_transform = *reinterpret_cast<unity_engine::transform**>(v4 + *(reinterpret_cast<uint64_t*>(_this) + 14)); // get next child in queue
			const int32_t v5 = transform_count_nodes_deep_detour(next_transform, map); // count the next child
			if (v5 == 0) // flag was triggered
			{
				*(reinterpret_cast<uint64_t*>(_this) + 16) = 0; // set children of toe to 0
				return v3; // return already counted transforms
			}
			++v1; // child_increment
			v4 += 8; // child queue increment
			v3 += v5; // increment total transforms found
		}
		while (static_cast<uint64_t>(v1) < *(reinterpret_cast<uint64_t*>(_this) + 16)); // while child_increment < total children in transform
	}
	return v3;
}
```
