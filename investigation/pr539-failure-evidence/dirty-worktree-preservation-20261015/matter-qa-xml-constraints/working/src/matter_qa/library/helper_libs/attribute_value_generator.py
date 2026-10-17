"""
Attribute Value Generator for Matter Protocol Testing.

This module provides functionality to generate random valid values for Matter
protocol attributes based on their data types and constraints.
"""

import logging
import random
import string
from dataclasses import MISSING
from enum import Enum, Flag
from typing import Annotated, Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple, Type, Union, get_args, get_origin

import aenum
from matter.tlv import float32, uint

from matter_qa.library.base_test_classes.models.matter_device_models import *
from matter_qa.library.helper_libs.constraint_parser import ConstraintParser
from matter_qa.library.helper_libs.exceptions import IterationError
from matter_qa.library.helper_libs.matter_type_mapper import MatterTypeMapper
from matter_qa.library.helper_libs.uint_tlv import *

log = logging.getLogger(__name__)


class ValueGeneratorConfig:
    """Configuration constants for value generation."""

    # String generation
    DEFAULT_STRING_MIN_LENGTH = 1
    DEFAULT_STRING_MAX_LENGTH = 32
    DEFAULT_FALLBACK_STRING = "default"

    # Bytes generation
    BITS_PER_BYTE = 8
    DEFAULT_BYTES_MIN_LENGTH = 1
    DEFAULT_BYTES_MAX_LENGTH = 32
    DEFAULT_FALLBACK_BYTES = b"\x00"

    # List generation
    DEFAULT_LIST_MIN_COUNT = 1
    DEFAULT_LIST_MAX_COUNT = 3
    DEFAULT_LIST_MAX_SIZE = 5
    MINIMUM_LIST_ELEMENT_COUNT = 1  # Ensure at least one element in generated lists
    DEFAULT_FALLBACK_LIST: list = []  # Note: use field() if this becomes a dataclass

    # Numeric generation
    DEFAULT_FLOAT_MIN = 0.0
    DEFAULT_FLOAT_MAX = 1000.0
    DEFAULT_INT_MIN = 0
    DEFAULT_INT_MAX = 65535
    DEFAULT_BITMAP_MIN = 0
    DEFAULT_BITMAP_MAX = 0xFF
    DEFAULT_FALLBACK_INT = 0
    DEFAULT_FALLBACK_BOOL = False
    DEFAULT_FALLBACK_FLOAT = 0.0

    # Recursion limits
    MAX_RECURSION_DEPTH = 10
    CIRCULAR_REFERENCE_MIN_DEPTH = 2


class RecursionTracker:
    """Thread-safe tracker for recursion depth and visited types."""

    def __init__(self, max_depth: int = ValueGeneratorConfig.MAX_RECURSION_DEPTH):
        self.max_depth = max_depth
        self._depth = 0
        self._visited_types: Set[str] = set()

    def reset(self) -> None:
        """Reset tracking state for a new generation cycle."""
        self._depth = 0
        self._visited_types.clear()

    def increment_depth(self) -> int:
        """Increment and return current depth."""
        self._depth += 1
        return self._depth

    def decrement_depth(self) -> None:
        """Decrement current depth."""
        self._depth = max(0, self._depth - 1)

    @property
    def current_depth(self) -> int:
        return self._depth

    def is_max_depth_exceeded(self) -> bool:
        return self._depth > self.max_depth

    def mark_type_visited(self, type_key: str) -> None:
        self._visited_types.add(type_key)

    def unmark_type_visited(self, type_key: str) -> None:
        self._visited_types.discard(type_key)

    def is_type_visited(self, type_key: str) -> bool:
        return type_key in self._visited_types


class TypeClassifier:
    """Classifies Matter data types into categories for value generation."""

    SIGNED_INT_TYPES = (int, Int8, Int16, Int32, Int64)
    UNSIGNED_INT_TYPES = (uint, UInt8, UInt16, UInt24, UInt32, UInt64)
    FLOAT_TYPES = (float, float32)

    @classmethod
    def is_boolean(cls, data_type: Type) -> bool:
        """Check if type is boolean."""
        return data_type is bool

    @classmethod
    def is_bitmap(cls, data_type: Type) -> bool:
        """Check if type is a bitmap/flag type."""
        try:
            if isinstance(data_type, type):
                if issubclass(data_type, (Flag, aenum.Flag)):
                    return True

            if hasattr(data_type, "__name__") and "bitmap" in data_type.__name__.lower():
                return True

            if hasattr(data_type, "__mro__"):
                for base in data_type.__mro__:
                    base_name = base.__name__.lower()
                    if "bitmap" in base_name or "flag" in base_name:
                        return True

            if hasattr(data_type, "__class__"):
                class_name = data_type.__class__.__name__.lower()
                if "flag" in class_name:
                    return True

        except TypeError:
            pass
        return False

    @classmethod
    def is_enum(cls, data_type: Type) -> bool:
        """Check if type is an enum (excluding bitmaps)."""
        if cls.is_bitmap(data_type):
            return False

        try:
            if isinstance(data_type, type):
                if issubclass(data_type, (Enum, aenum.Enum)):
                    return True

            if hasattr(data_type, "__mro__"):
                for base in data_type.__mro__:
                    base_name = base.__name__.lower()
                    if "enum" in base_name and "flag" not in base_name:
                        return True

        except TypeError:
            pass
        return False

    @classmethod
    def is_signed_integer(cls, data_type: Type) -> bool:
        """Check if type is a signed integer."""
        if cls.is_boolean(data_type) or cls.is_bitmap(data_type) or cls.is_enum(data_type):
            return False

        try:
            if data_type in cls.SIGNED_INT_TYPES:
                return True
            if isinstance(data_type, type) and issubclass(data_type, int):
                return not issubclass(data_type, uint)
        except TypeError:
            pass
        return False

    @classmethod
    def is_unsigned_integer(cls, data_type: Type) -> bool:
        """Check if type is an unsigned integer."""
        if cls.is_boolean(data_type) or cls.is_bitmap(data_type) or cls.is_enum(data_type):
            return False

        try:
            if data_type in cls.UNSIGNED_INT_TYPES:
                return True
            if isinstance(data_type, type) and issubclass(data_type, uint):
                return True
        except TypeError:
            pass
        return False

    @classmethod
    def is_float(cls, data_type: Type) -> bool:
        """Check if type is a floating-point type."""
        return data_type in cls.FLOAT_TYPES

    @classmethod
    def is_string(cls, data_type: Type) -> bool:
        """Check if type is a string."""
        return data_type is str

    @classmethod
    def is_bytes(cls, data_type: Type) -> bool:
        """Check if type is bytes."""
        return data_type is bytes

    @classmethod
    def is_struct(cls, data_type: Type) -> bool:
        """Check if type is a struct/dataclass."""
        return hasattr(data_type, "__dataclass_fields__") or isinstance(data_type, type)

    @classmethod
    def is_list(cls, data_type: Type) -> bool:
        """Check if type is a list."""
        return get_origin(data_type) is list


class TypeResolver:
    """Resolves and unwraps complex type definitions."""

    @staticmethod
    def unwrap_type(wrapped_type: Any) -> Any:
        """Unwrap wrapper types (descriptors, Optional/Union, Nullable) to concrete type."""
        # Handle cluster object field descriptors
        try:
            if hasattr(wrapped_type, "Type") and getattr(wrapped_type, "Type") is not None:
                return getattr(wrapped_type, "Type")
            if hasattr(wrapped_type, "attribute_type") and getattr(wrapped_type, "attribute_type") is not None:
                return getattr(wrapped_type, "attribute_type")
        except Exception:
            pass

        # Handle Union types (prefer first non-None arg)
        try:
            origin = get_origin(wrapped_type)
            if origin is Union:
                args = [a for a in get_args(wrapped_type) if a is not type(None)]
                if args:
                    return args[0]
        except Exception:
            pass

        # Handle typing wrappers with __args__
        try:
            if hasattr(wrapped_type, "__args__") and getattr(wrapped_type, "__args__", None):
                args = [a for a in getattr(wrapped_type, "__args__", []) if a is not type(None)]
                if args:
                    return args[0]
        except Exception:
            pass

        # Return origin if available
        try:
            origin = get_origin(wrapped_type)
            if origin:
                return origin
        except Exception:
            pass

        return wrapped_type

    @staticmethod
    def resolve_forward_reference(
        type_ref: Any,
        cluster_info: Optional[ClusterInfo] = None,
        attribute_info: Optional[AttributeInfo] = None
    ) -> Any:
        """Resolve ForwardRef or string type names via MatterTypeMapper."""
        cluster_obj = cluster_info.cluster_obj if cluster_info else None
        attribute_obj = attribute_info.attribute_obj if attribute_info else None

        # Handle ForwardRef
        try:
            forward_arg = getattr(type_ref, "__forward_arg__", None)
            if forward_arg:
                mapped = MatterTypeMapper.resolve_type(forward_arg, cluster_obj, attribute_obj)
                if mapped:
                    return mapped
        except Exception:
            pass

        # Handle string type names
        if isinstance(type_ref, str):
            return MatterTypeMapper.resolve_type(type_ref, cluster_obj, attribute_obj)

        return type_ref

    @staticmethod
    def get_list_element_type(list_type: Type) -> Type:
        """Extract element type from a List type."""
        args = get_args(list_type)
        return args[0] if args else Any


class PrimitiveValueGenerator:
    """Generates random values for primitive data types."""

    @staticmethod
    def generate_boolean() -> bool:
        """Generate a random boolean value."""
        return random.choice([True, False])

    @staticmethod
    def generate_integer(
        constraints: AttributeConstraints,
        data_type: Optional[Type] = None
    ) -> int:
        """Generate a random integer respecting constraints and type limits."""
        if constraints.allowed_values:
            return random.choice([int(v) for v in constraints.allowed_values])

        # Determine type-based limits
        type_min = ValueGeneratorConfig.DEFAULT_INT_MIN
        type_max = ValueGeneratorConfig.DEFAULT_INT_MAX

        if data_type is not None:
            if hasattr(data_type, 'MIN_VALUE'):
                type_min = data_type.MIN_VALUE
            if hasattr(data_type, 'MAX_VALUE'):
                type_max = data_type.MAX_VALUE

        # Apply constraint limits, clamped to type limits
        min_val = int(constraints.min_value) if constraints.min_value is not None else type_min
        max_val = int(constraints.max_value) if constraints.max_value is not None else type_max

        min_val = max(min_val, type_min)
        max_val = min(max_val, type_max)

        if min_val > max_val:
            min_val, max_val = max_val, min_val

        return random.randint(min_val, max_val)

    @staticmethod
    def generate_float(constraints: AttributeConstraints) -> float:
        """Generate a random float respecting constraints."""
        min_val = float(constraints.min_value) if constraints.min_value is not None else ValueGeneratorConfig.DEFAULT_FLOAT_MIN
        max_val = float(constraints.max_value) if constraints.max_value is not None else ValueGeneratorConfig.DEFAULT_FLOAT_MAX

        if min_val > max_val:
            min_val, max_val = max_val, min_val

        return random.uniform(min_val, max_val)

    @staticmethod
    def generate_string(constraints: AttributeConstraints) -> str:
        """Generate a random string respecting length constraints."""
        min_len, max_len = PrimitiveValueGenerator._get_length_bounds(
            constraints,
            ValueGeneratorConfig.DEFAULT_STRING_MIN_LENGTH,
            ValueGeneratorConfig.DEFAULT_STRING_MAX_LENGTH
        )

        length = random.randint(min_len, max_len)

        # If allowed_values contains integers, use the first one as the length
        if constraints.allowed_values:
            if all(isinstance(v, int) for v in constraints.allowed_values):
                length = int(constraints.allowed_values[0])

        charset = string.ascii_letters + string.digits
        return ''.join(random.choices(charset, k=length))

    @staticmethod
    def generate_bytes(constraints: AttributeConstraints) -> bytes:
        """Generate random bytes respecting length constraints."""
        min_len, max_len = PrimitiveValueGenerator._get_length_bounds(
            constraints,
            ValueGeneratorConfig.DEFAULT_BYTES_MIN_LENGTH,
            ValueGeneratorConfig.DEFAULT_BYTES_MAX_LENGTH
        )

        length = random.randint(min_len, max_len)
        return bytes(random.getrandbits(ValueGeneratorConfig.BITS_PER_BYTE) for _ in range(length))

    @staticmethod
    def _get_length_bounds(
        constraints: AttributeConstraints,
        default_min: int,
        default_max: int
    ) -> Tuple[int, int]:
        """Extract length bounds from constraints with defaults."""
        if constraints.length_range:
            min_len, max_len = constraints.length_range
        elif constraints.max_length:
            min_len = constraints.min_length or default_min
            max_len = constraints.max_length
        else:
            min_len, max_len = default_min, default_max

        if min_len > max_len:
            min_len, max_len = max_len, min_len

        return min_len, max_len


class EnumValueGenerator:
    """Generates random values for enum and bitmap types."""

    UNKNOWN_SENTINEL_NAME = "kUnknownEnumValue"

    @staticmethod
    def generate_enum(enum_type: Type, constraints: AttributeConstraints) -> Any:
        """Generate a random enum value."""
        try:
            members = [m for m in enum_type]
            # Filter out unknown sentinel values
            members = [m for m in members if getattr(m, "name", "") != EnumValueGenerator.UNKNOWN_SENTINEL_NAME]

            if constraints.allowed_values:
                allowed = EnumValueGenerator._filter_allowed_values(enum_type, constraints.allowed_values)
                if allowed:
                    return random.choice(allowed)

            if members:
                return random.choice(members)

        except Exception:
            pass

        # Fallback to integer generation
        return PrimitiveValueGenerator.generate_integer(constraints)

    @staticmethod
    def generate_bitmap(bitmap_type: Type, constraints: AttributeConstraints) -> Any:
        """Generate a valid bitmap value based on defined flags."""
        log.debug(f"Generating bitmap for type {bitmap_type}")

        if constraints.allowed_values:
            return bitmap_type(random.choice(constraints.allowed_values))

        valid_members = EnumValueGenerator._get_valid_bitmap_members(bitmap_type)

        if not valid_members:
            max_val = int(constraints.max_value) if constraints.max_value is not None else ValueGeneratorConfig.DEFAULT_BITMAP_MAX
            return bitmap_type(random.randint(ValueGeneratorConfig.DEFAULT_BITMAP_MIN, max_val))

        # Randomly combine flags
        num_flags = random.randint(0, len(valid_members))
        selected_members = random.sample(valid_members, num_flags)

        combined_value = 0
        for member in selected_members:
            try:
                combined_value |= int(member.value)
            except (ValueError, TypeError, AttributeError):
                try:
                    combined_value |= int(member)
                except Exception:
                    pass

        return bitmap_type(combined_value)

    @staticmethod
    def _filter_allowed_values(enum_type: Type, allowed_values: List[Any]) -> List[Any]:
        """Filter and convert allowed values to enum members."""
        allowed = []
        for value in allowed_values:
            try:
                allowed.append(enum_type(value))
            except Exception:
                if isinstance(value, enum_type):
                    allowed.append(value)
        return allowed

    @staticmethod
    def _get_valid_bitmap_members(bitmap_type: Type) -> List[Any]:
        """Get valid (non-sentinel) bitmap members."""
        valid_members = []
        try:
            for member in bitmap_type:
                member_name = getattr(member, 'name', str(member))
                if 'unknown' in member_name.lower() or member_name.startswith('_'):
                    continue
                valid_members.append(member)
        except Exception as e:
            log.debug(f"Could not iterate bitmap members for {bitmap_type}: {e}")
        return valid_members


class AttributeValueGenerator:
    """
    Generate random valid values for Matter protocol attributes.

    This class handles value generation for all Matter data types including
    primitives, enums, bitmaps, structs, and lists with proper constraint handling.
    """

    MAX_RECURSION_DEPTH = ValueGeneratorConfig.MAX_RECURSION_DEPTH

    def __init__(self):
        self._recursion_tracker = RecursionTracker(self.MAX_RECURSION_DEPTH)

    async def generate_value(
        self,
        attribute_info: AttributeInfo,
        endpoint_info: EndpointInfo,
        cluster_info: ClusterInfo,
        read_attr_fn: Optional[Callable[..., Awaitable[Any]]] = None
    ) -> Any:
        """
        Generate a random valid value for an attribute.

        Args:
            attribute_info: Information about the attribute to generate a value for.
            endpoint_info: Information about the endpoint containing the attribute.
            cluster_info: Information about the cluster containing the attribute.
            read_attr_fn: Optional async function to read attribute values for constraint resolution.

        Returns:
            A randomly generated value that satisfies the attribute's constraints.
        """
        self._recursion_tracker.reset()

        data_type = attribute_info.data_type

        # Handle List types specially
        if TypeClassifier.is_list(data_type):
            return await self._generate_list_attribute(
                data_type, attribute_info, endpoint_info, cluster_info, read_attr_fn
            )

        # Unwrap and resolve type
        data_type = TypeResolver.unwrap_type(data_type)
        data_type = TypeResolver.resolve_forward_reference(data_type, cluster_info, attribute_info)

        constraints = attribute_info.constraints or AttributeConstraints()
        resolved_constraints = await self._resolve_constraints(
            constraints, endpoint_info, cluster_info, read_attr_fn
        )

        if (getattr(cluster_info, "cluster_name", None) == "ValveConfigurationAndControl"
                and attribute_info.attribute_name == "DefaultOpenLevel"
                and any(attribute.attribute_name == "LevelStep" for attribute in cluster_info.Attributes)):
            if read_attr_fn is not None:
                step_attribute = next(attribute for attribute in cluster_info.Attributes if attribute.attribute_name == "LevelStep")
                level_step = await read_attr_fn(cluster=cluster_info.cluster_obj, attribute=step_attribute.attribute_obj,
                                               endpoint=endpoint_info.endpoint_id)
            else:
                level_step = await ConstraintParser.resolve_constraint_value_async(
                    "attribute:LevelStep", endpoint_info, cluster_info)
            if not isinstance(level_step, int) or isinstance(level_step, bool) or not 1 <= level_step <= 100:
                raise IterationError(f"Invalid LevelStep for DefaultOpenLevel generation: {level_step!r}")
            minimum = max(1, int(resolved_constraints.min_value) if resolved_constraints.min_value is not None else 1)
            maximum = min(100, int(resolved_constraints.max_value) if resolved_constraints.max_value is not None else 100)
            candidates = resolved_constraints.allowed_values or range(minimum, maximum + 1)
            resolved_constraints.allowed_values = [
                int(value) for value in candidates
                if minimum <= int(value) <= maximum and (int(value) == 100 or int(value) % level_step == 0)
            ]
            if not resolved_constraints.allowed_values:
                raise IterationError("No DefaultOpenLevel satisfies the range and LevelStep constraints")

        log.debug(
            f"Generating value for attribute {attribute_info.attribute_name} "
            f"of type {data_type} with constraints {resolved_constraints}"
        )

        current_value = attribute_info.value
        generated_value = self._generate_typed_value(data_type, resolved_constraints, cluster_info, attribute_info)
        log.info(f"Generated value for attribute {attribute_info.attribute_name}: {generated_value}")

        # Ensure generated value differs from existing value
        if generated_value == current_value and current_value is not None:
            log.info(f"Generated value is the same as existing value ({current_value}), generating distinct value...")

            # For boolean types, always invert the current value to guarantee a different value
            if TypeClassifier.is_boolean(data_type):
                generated_value = not current_value
                log.info(f"Boolean attribute: inverted value to {generated_value}")
            else:
                # For other types, try multiple regeneration attempts
                max_attempts = ValueGeneratorConfig.MAX_RECURSION_DEPTH
                for attempt in range(max_attempts):
                    generated_value = self._generate_typed_value(data_type, resolved_constraints, cluster_info, attribute_info)
                    if generated_value != current_value:
                        log.info(f"Generated distinct value on attempt {attempt + 1}: {generated_value}")
                        break
                else:
                    log.warning(
                        f"Could not generate distinct value for {attribute_info.attribute_name} "
                        f"after {max_attempts} attempts, using last generated value: {generated_value}"
                    )

        return generated_value

    async def _generate_list_attribute(
        self,
        list_type: Type,
        attribute_info: AttributeInfo,
        endpoint_info: EndpointInfo,
        cluster_info: ClusterInfo,
        read_attr_fn: Optional[Callable[..., Awaitable[Any]]]
    ) -> List[Any]:
        """Generate a list attribute value."""
        element_type = TypeResolver.get_list_element_type(list_type)
        element_type = TypeResolver.unwrap_type(element_type)
        element_type = TypeResolver.resolve_forward_reference(element_type, cluster_info, attribute_info)

        constraints = attribute_info.constraints or AttributeConstraints()
        resolved_constraints = await self._resolve_constraints(
            constraints, endpoint_info, cluster_info, read_attr_fn
        )

        return self._generate_list(element_type, resolved_constraints, cluster_info, attribute_info)

    async def _resolve_constraints(
        self,
        constraints: AttributeConstraints,
        endpoint_info: EndpointInfo,
        cluster_info: ClusterInfo,
        read_attr_fn: Optional[Callable[..., Awaitable[Any]]] = None
    ) -> AttributeConstraints:
        """Resolve constraint fields that reference other attributes."""
        resolved = AttributeConstraints()

        for key, value in constraints.__dict__.items():
            if isinstance(value, str) and (value.startswith("attribute:") or value.startswith("compute:")):
                resolved_value = await ConstraintParser.resolve_constraint_value_async(
                    value, endpoint_info, cluster_info, read_attr_fn
                )
                # Check if resolved value is a decode failure or error object
                log.info(f"Resolved constraint {key} reference '{value}' to: {resolved_value}")
                if resolved_value is not None:
                    type_name = type(resolved_value).__name__
                    if 'Failure' in type_name or 'Error' in type_name:
                        log.warning(f"Constraint {key}={value} resolved to error: {resolved_value}, ignoring")
                        resolved_value = None
                setattr(resolved, key, resolved_value)
            else:
                setattr(resolved, key, value)

        return resolved

    def _generate_typed_value(
        self,
        data_type: Type,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo],
        attribute_info: Optional[AttributeInfo]
    ) -> Any:
        """Generate a value based on the specific data type."""
        # Boolean (must check before int since bool is subclass of int)
        if TypeClassifier.is_boolean(data_type):
            return PrimitiveValueGenerator.generate_boolean()

        # Unsigned integers
        if TypeClassifier.is_unsigned_integer(data_type):
            return PrimitiveValueGenerator.generate_integer(constraints, data_type)

        # Signed integers
        if TypeClassifier.is_signed_integer(data_type):
            return PrimitiveValueGenerator.generate_integer(constraints, data_type)

        # Floats
        if TypeClassifier.is_float(data_type):
            return PrimitiveValueGenerator.generate_float(constraints)

        # Strings
        if TypeClassifier.is_string(data_type):
            return PrimitiveValueGenerator.generate_string(constraints)

        # Bytes
        if TypeClassifier.is_bytes(data_type):
            return PrimitiveValueGenerator.generate_bytes(constraints)

        # Bitmaps (must check before enum since Flag is subclass of Enum)
        if TypeClassifier.is_bitmap(data_type):
            return EnumValueGenerator.generate_bitmap(data_type, constraints)

        # Enums
        if TypeClassifier.is_enum(data_type):
            return EnumValueGenerator.generate_enum(data_type, constraints)

        # Structs/dataclasses
        if TypeClassifier.is_struct(data_type):
            resolved_type = TypeResolver.resolve_forward_reference(data_type, cluster_info, attribute_info)
            return self._generate_struct(resolved_type, constraints, cluster_info, attribute_info)

        # Fallback: try default constructor
        return self._try_default_construction(data_type)

    def _generate_struct(
        self,
        struct_type: Type,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo] = None,
        attribute_info: Optional[AttributeInfo] = None,
        depth: int = 0
    ) -> Any:
        """Generate a struct instance with randomly generated field values."""
        if depth > self.MAX_RECURSION_DEPTH:
            log.warning(f"Max recursion depth exceeded for struct type {struct_type}")
            return None

        type_key = str(struct_type)
        if self._recursion_tracker.is_type_visited(type_key) and depth > ValueGeneratorConfig.CIRCULAR_REFERENCE_MIN_DEPTH:
            log.warning(f"Circular type reference detected for {struct_type}")
            return None

        self._recursion_tracker.mark_type_visited(type_key)

        try:
            struct_type = self._resolve_struct_type(struct_type, cluster_info, attribute_info)

            if not callable(struct_type):
                log.warning(f"Cannot construct struct of type {struct_type}")
                return None

            # Build field name mapping for dataclass
            field_name_map = self._build_field_name_map(struct_type)

            # Try different generation strategies in order of preference
            result = self._try_generate_from_attribute_info(
                struct_type, attribute_info, field_name_map, cluster_info, constraints, depth
            )
            if result is not None:
                return result

            result = self._try_generate_from_xml_definition(
                struct_type, cluster_info, field_name_map, depth
            )
            if result is not None:
                return result

            result = self._try_generate_from_dataclass_fields(
                struct_type, constraints, cluster_info, depth
            )
            if result is not None:
                return result

            log.warning(f"Unable to generate struct for type {struct_type}")
            return None

        finally:
            self._recursion_tracker.unmark_type_visited(type_key)

    def _resolve_struct_type(
        self,
        struct_type: Type,
        cluster_info: Optional[ClusterInfo],
        attribute_info: Optional[AttributeInfo]
    ) -> Type:
        """Resolve forward references and unwrap descriptors for struct type."""
        struct_type = TypeResolver.resolve_forward_reference(struct_type, cluster_info, attribute_info)

        try:
            if hasattr(struct_type, "Type") and isinstance(getattr(struct_type, "Type"), type):
                struct_type = getattr(struct_type, "Type")
            if hasattr(struct_type, "attribute_type") and isinstance(getattr(struct_type, "attribute_type"), type):
                struct_type = getattr(struct_type, "attribute_type")
        except Exception:
            pass

        return struct_type

    def _build_field_name_map(self, struct_type: Type) -> Dict[str, str]:
        """Build case-insensitive field name mapping for dataclass."""
        field_map = {}
        if hasattr(struct_type, "__dataclass_fields__"):
            for real_name in struct_type.__dataclass_fields__.keys():
                field_map[real_name.lower()] = real_name
        return field_map

    def _try_generate_from_attribute_info(
        self,
        struct_type: Type,
        attribute_info: Optional[AttributeInfo],
        field_name_map: Dict[str, str],
        cluster_info: Optional[ClusterInfo],
        constraints: AttributeConstraints,
        depth: int
    ) -> Optional[Any]:
        """Try to generate struct using attribute_info.struct_fields."""
        if not attribute_info or not attribute_info.struct_fields:
            return None

        kwargs = {}
        for struct_field in attribute_info.struct_fields:
            field_name = struct_field.field_name
            field_type = struct_field.data_type or struct_field.field_type
            field_constraints = struct_field.constraints or AttributeConstraints()

            value = self._generate_struct_field_value(
                field_type, field_name, field_constraints,
                cluster_info, attribute_info,
                struct_field_info=struct_field, depth=depth + 1
            )

            if value is None:
                value = self._get_fallback_value(field_type)

            target_name = field_name_map.get(
                field_name.lower(),
                field_name if field_name.isidentifier() else field_name.lower()
            )
            kwargs[target_name] = value

        try:
            return struct_type(**kwargs)
        except Exception as e:
            log.debug(f"Struct construction from attribute_info failed: {e}", exc_info=True)
            return None

    def _try_generate_from_xml_definition(
        self,
        struct_type: Type,
        cluster_info: Optional[ClusterInfo],
        field_name_map: Dict[str, str],
        depth: int
    ) -> Optional[Any]:
        """Try to generate struct using XML cluster definition."""
        struct_def = self._find_struct_definition(struct_type, cluster_info)
        if struct_def is None:
            return None

        kwargs = {}
        fields = struct_def.get('field') or []
        fields = fields if isinstance(fields, list) else [fields]

        for field in fields:
            field_name = field.get('@name') or field.get('name')
            field_type_xml = field.get('@type') or field.get('type')
            constraint_dict = field.get('constraint')

            cluster_obj = cluster_info.cluster_obj if cluster_info else None
            mapped_type = MatterTypeMapper.resolve_type(field_type_xml, cluster_obj)

            field_constraints = (
                ConstraintParser.parse_constraint(constraint_dict, cluster_info)
                if constraint_dict else AttributeConstraints()
            )

            value = self._generate_struct_field_value(
                mapped_type, field_name, field_constraints,
                cluster_info, None, depth=depth + 1
            )

            if value is None:
                value = self._get_fallback_value(mapped_type)

            target_name = field_name_map.get(
                field_name.lower(),
                field_name if field_name.isidentifier() else field_name.lower()
            )
            kwargs[target_name] = value

        try:
            return struct_type(**kwargs)
        except Exception as e:
            log.debug(f"Struct construction from XML failed: {e}", exc_info=True)
            return None

    def _find_struct_definition(
        self,
        struct_type: Type,
        cluster_info: Optional[ClusterInfo]
    ) -> Optional[Dict[str, Any]]:
        """Find struct definition in cluster XML."""
        if not cluster_info or not getattr(cluster_info, "definition", None):
            return None

        data_types = (
            cluster_info.definition.get('cluster', {}).get('dataTypes')
            or cluster_info.definition.get('dataTypes')
            or {}
        )

        structs = data_types.get('struct')
        if not structs:
            return None

        structs_list = structs if isinstance(structs, list) else [structs]
        struct_name = struct_type.__name__ if hasattr(struct_type, '__name__') else str(struct_type)

        for struct_def in structs_list:
            name = struct_def.get('@name') or struct_def.get('name')
            if name and struct_name.lower() == name.lower():
                return struct_def

        return None

    def _try_generate_from_dataclass_fields(
        self,
        struct_type: Type,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo],
        depth: int
    ) -> Optional[Any]:
        """Try to generate struct using dataclass introspection."""
        if not hasattr(struct_type, "__dataclass_fields__"):
            return None

        kwargs = {}
        for field_name, field_info in struct_type.__dataclass_fields__.items():
            field_type = self._unwrap_field_type(field_info.type)

            value = self._generate_struct_field_value(
                field_type, field_name, constraints,
                cluster_info, None, depth=depth + 1
            )

            if value is None:
                value = self._get_field_default_value(field_type, field_info)

            kwargs[field_name] = value

        try:
            return struct_type(**kwargs)
        except Exception as e:
            log.debug(f"Dataclass construction failed: {e}", exc_info=True)
            return None

    def _unwrap_field_type(self, field_type: Type) -> Type:
        """Unwrap Annotated and Union types from a field type."""
        try:
            if get_origin(field_type) is Annotated:
                field_type = get_args(field_type)[0]
        except Exception:
            pass

        try:
            if get_origin(field_type) is Union:
                args = [a for a in get_args(field_type) if a is not type(None)]
                if args:
                    field_type = args[0]
        except Exception:
            pass

        return field_type

    def _get_field_default_value(self, field_type: Type, field_info: Any) -> Any:
        """Get default value for a dataclass field."""
        fallback = self._get_fallback_value(field_type)
        if fallback is not None:
            return fallback

        if field_info.default is not MISSING:
            return field_info.default

        if getattr(field_info, "default_factory", MISSING) is not MISSING:
            try:
                return field_info.default_factory()
            except Exception:
                pass

        return None

    def _generate_struct_field_value(
        self,
        field_type: Type,
        field_name: str,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo] = None,
        attribute_info: Optional[AttributeInfo] = None,
        struct_field_info: Optional[StructFieldInfo] = None,
        depth: int = 0
    ) -> Any:
        """Generate a value for an individual struct field."""
        if depth > self.MAX_RECURSION_DEPTH:
            log.warning(f"Max recursion depth for field {field_name}")
            return self._get_fallback_value(field_type)

        field_type = self._resolve_field_type(field_type, cluster_info, attribute_info)

        # Handle nested fields from struct_field_info
        if struct_field_info and struct_field_info.nested_fields:
            return self._generate_from_nested_fields(
                field_type, struct_field_info, cluster_info, attribute_info, depth
            )

        # Handle list fields
        if TypeClassifier.is_list(field_type):
            element_type = TypeResolver.get_list_element_type(field_type)
            return self._generate_list(element_type, constraints, cluster_info, attribute_info, depth)

        return self._generate_typed_value(field_type, constraints, cluster_info, attribute_info)

    def _resolve_field_type(
        self,
        field_type: Type,
        cluster_info: Optional[ClusterInfo],
        attribute_info: Optional[AttributeInfo]
    ) -> Type:
        """Resolve field type from ForwardRef or string."""
        # Handle ForwardRef
        try:
            forward_arg = getattr(field_type, "__forward_arg__", None)
            if forward_arg:
                cluster_obj = cluster_info.cluster_obj if cluster_info else None
                resolved = MatterTypeMapper.find_cluster_type(forward_arg, cluster_obj)
                if not resolved:
                    resolved = MatterTypeMapper.find_global_type(forward_arg)
                if resolved:
                    return resolved
        except Exception:
            pass

        # Handle string type names
        if isinstance(field_type, str):
            cluster_obj = cluster_info.cluster_obj if cluster_info else None
            attribute_obj = attribute_info.attribute_obj if attribute_info else None
            return MatterTypeMapper.resolve_type(field_type, cluster_obj, attribute_obj)

        return field_type

    def _generate_from_nested_fields(
        self,
        field_type: Type,
        struct_field_info: StructFieldInfo,
        cluster_info: Optional[ClusterInfo],
        attribute_info: Optional[AttributeInfo],
        depth: int
    ) -> Any:
        """Generate value from nested field definitions."""
        origin = get_origin(field_type)

        if origin is list:
            return self._generate_list_from_nested_fields(
                field_type, struct_field_info, cluster_info, attribute_info, depth
            )

        # Nested struct case
        resolved_type = TypeResolver.unwrap_type(field_type)
        resolved_type = TypeResolver.resolve_forward_reference(resolved_type, cluster_info, attribute_info)

        return self._build_struct_from_nested_fields(
            resolved_type, struct_field_info.nested_fields, cluster_info, depth
        )

    def _generate_list_from_nested_fields(
        self,
        list_type: Type,
        struct_field_info: StructFieldInfo,
        cluster_info: Optional[ClusterInfo],
        attribute_info: Optional[AttributeInfo],
        depth: int
    ) -> List[Any]:
        """Generate a list from nested field definitions."""
        element_type = TypeResolver.get_list_element_type(list_type)
        element_type = TypeResolver.unwrap_type(element_type)
        element_type = TypeResolver.resolve_forward_reference(element_type, cluster_info, attribute_info)

        max_count = self._resolve_max_count(struct_field_info.constraints, cluster_info)

        try:
            size = random.randint(
                ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT, min(
                    ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT, max_count))
        except TypeError:
            size = random.randint(ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT, ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT)

        result = []
        for _ in range(size):
            value = self._build_struct_from_nested_fields(
                element_type, struct_field_info.nested_fields, cluster_info, depth
            )
            result.append(value)

        return result

    def _resolve_max_count(
        self,
        constraints: Optional[AttributeConstraints],
        cluster_info: Optional[ClusterInfo]
    ) -> int:
        """Resolve max_count from constraints, handling various formats."""
        if not constraints:
            return ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

        max_count = getattr(constraints, "max_count", None)
        if max_count is None:
            return ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

        if isinstance(max_count, int):
            return max_count

        if isinstance(max_count, str):
            # Try direct numeric parsing
            try:
                return int(max_count, 0)
            except Exception:
                pass

            # Handle attribute references
            if max_count.startswith("attribute:") and cluster_info:
                return self._resolve_attribute_reference(max_count, cluster_info) or ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

        return ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

    def _resolve_attribute_reference(
        self,
        reference: str,
        cluster_info: ClusterInfo
    ) -> Optional[int]:
        """Resolve an attribute reference to an integer value."""
        ref_path = reference.split(":", 1)[1]
        ref_name = ref_path.split(".", 1)[0]

        for attr in getattr(cluster_info, "Attributes", []):
            if attr.attribute_name == ref_name:
                attr_value = getattr(attr, "value", None)

                if isinstance(attr_value, (int, float)):
                    return int(attr_value)

                if isinstance(attr_value, dict) and "." in ref_path:
                    _, field = ref_path.split(".", 1)
                    try:
                        return int(attr_value.get(field))
                    except Exception:
                        pass

        return None

    def _build_struct_from_nested_fields(
        self,
        target_type: Type,
        nested_fields: List[StructFieldInfo],
        cluster_info: Optional[ClusterInfo],
        depth: int
    ) -> Any:
        """Build a struct instance from nested field definitions."""
        if depth > self.MAX_RECURSION_DEPTH:
            log.warning(f"Max recursion depth in nested fields for {target_type}")
            return None

        kwargs = {}
        field_name_map = self._build_field_name_map(target_type)

        for nested_field in nested_fields:
            field_name = nested_field.field_name
            field_type = nested_field.data_type or nested_field.field_type
            field_constraints = nested_field.constraints or AttributeConstraints()

            value = self._generate_struct_field_value(
                field_type, field_name, field_constraints,
                cluster_info, None,
                struct_field_info=nested_field, depth=depth + 1
            )

            if value is None:
                value = self._get_fallback_value(field_type)

            target_key = field_name_map.get(
                field_name.lower(),
                field_name if field_name.isidentifier() else field_name.lower()
            )
            kwargs[target_key] = value

        try:
            return target_type(**kwargs)
        except Exception:
            return kwargs

    def _generate_list(
        self,
        element_type: Type,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo] = None,
        attribute_info: Optional[AttributeInfo] = None,
        depth: int = 0
    ) -> List[Any]:
        """Generate a list of elements."""
        if depth > self.MAX_RECURSION_DEPTH:
            log.warning(f"Max recursion depth in list generation for {element_type}")
            return []

        element_type = TypeResolver.unwrap_type(element_type)
        element_type = TypeResolver.resolve_forward_reference(element_type, cluster_info, attribute_info)

        min_count, max_count = self._get_count_bounds(constraints)
        size = random.randint(min_count, min(max_count, ValueGeneratorConfig.DEFAULT_LIST_MAX_SIZE))

        result = []
        for _ in range(size):
            value = self._generate_element_value(
                element_type, constraints, cluster_info, attribute_info, depth
            )
            if value is None:
                value = self._get_fallback_value(element_type)
            result.append(value)

        return result

    def _get_count_bounds(self, constraints: AttributeConstraints) -> Tuple[int, int]:
        """Get count bounds for list generation."""
        if constraints.count_range:
            min_count, max_count = constraints.count_range
        elif constraints.max_count:
            max_count = constraints.max_count if isinstance(
                constraints.max_count, int) else ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT
            min_count = constraints.min_count or ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT
        else:
            min_count = ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT
            max_count = ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

        try:
            min_count = int(min_count) if min_count is not None else ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT
            max_count = int(max_count) if max_count is not None else ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT
        except (ValueError, TypeError):
            min_count, max_count = ValueGeneratorConfig.DEFAULT_LIST_MIN_COUNT, ValueGeneratorConfig.DEFAULT_LIST_MAX_COUNT

        if min_count > max_count:
            min_count, max_count = max_count, min_count
        if min_count == 0 and max_count > 0:
            min_count = ValueGeneratorConfig.MINIMUM_LIST_ELEMENT_COUNT

        return min_count, max_count

    def _generate_element_value(
        self,
        element_type: Type,
        constraints: AttributeConstraints,
        cluster_info: Optional[ClusterInfo] = None,
        attribute_info: Optional[AttributeInfo] = None,
        depth: int = 0
    ) -> Any:
        """Generate a single element value for a list."""
        if depth > self.MAX_RECURSION_DEPTH:
            log.warning(f"Max recursion depth in element generation for {element_type}")
            return self._get_fallback_value(element_type)

        element_type = TypeResolver.unwrap_type(element_type)
        element_type = TypeResolver.resolve_forward_reference(element_type, cluster_info, attribute_info)

        return self._generate_typed_value(element_type, constraints, cluster_info, attribute_info)

    def _get_fallback_value(self, field_type: Type) -> Any:
        """Get a fallback value for a type when generation fails."""
        if field_type in (int, uint):
            return ValueGeneratorConfig.DEFAULT_FALLBACK_INT
        if field_type is bool:
            return ValueGeneratorConfig.DEFAULT_FALLBACK_BOOL
        if TypeClassifier.is_float(field_type):
            return ValueGeneratorConfig.DEFAULT_FALLBACK_FLOAT
        if field_type is str:
            return ValueGeneratorConfig.DEFAULT_FALLBACK_STRING
        if field_type is bytes:
            return ValueGeneratorConfig.DEFAULT_FALLBACK_BYTES

        if TypeClassifier.is_list(field_type):
            return []  # Return new list to avoid mutation issues

        try:
            return field_type()
        except Exception:
            return None

    def _try_default_construction(self, data_type: Type) -> Any:
        """Try to construct a value using the type's default constructor."""
        try:
            return data_type()
        except Exception:
            log.warning(f"Unknown data type {data_type}, generation failed.")
            return None


# Convenience function for backward compatibility
async def generate_attribute_value(
    attribute_info: AttributeInfo,
    endpoint_info: EndpointInfo,
    cluster_info: ClusterInfo,
    read_attr_fn: Optional[Callable[..., Awaitable[Any]]] = None
) -> Any:
    """
    Convenience function to generate an attribute value.

    This maintains backward compatibility with code expecting a module-level function.
    """
    generator = AttributeValueGenerator()
    return await generator.generate_value(attribute_info, endpoint_info, cluster_info, read_attr_fn)
