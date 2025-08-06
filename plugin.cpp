#include <hexsuite.hpp>

#ifndef GIT_COMMIT_ID
    #define GIT_COMMIT_ID "unknown"
#endif

#ifdef _DEBUG
    #pragma message("================== build in debug mode")
    #define DLOG(fmt, ...) msg("##### [bitfields] %s: " fmt "\n", __func__, ##__VA_ARGS__)
#else
    #pragma message("================== build in release mode")
    #define DLOG(fmt, ...)
#endif


qstring expr_to_string(cexpr_t* expr)
{
    if (!expr) return "";
    
    qstring result;
    
    switch (expr->op) {
        case cot_num:
            result.sprnt("0x%X", expr->n->_value);
            break;
            
        case cot_var:
            {
                lvar_t* lvar = &(expr->v.getv());
                const char* var_name = lvar->name.c_str();
                result.sprnt("%s", var_name ? var_name : "<unknown>");
            }
            break;
        
        case cot_obj:  // Object reference (global variable, function)
            {
                qstring out;
                if (get_ea_name(&out, expr->obj_ea)) {
                    result.sprnt("%s", out.c_str());
                } else {
                    result.sprnt("obj:0x%llX", expr->obj_ea);
                }
            }
            break;
            
        case cot_ptr:  // Pointer dereference (*ptr)
            result.sprnt("*%s", expr_to_string(expr->x).c_str());
            break;

        case cot_ref:  // Address-of operator (&var)
            result.sprnt("&%s", expr_to_string(expr->x).c_str());
            break;
        
        case cot_ne:  // Not equal comparison (!=)
            result.sprnt("(%s != %s)", 
                         expr_to_string(expr->x).c_str(), 
                         expr_to_string(expr->y).c_str());
            break;


        case cot_band:
            result.sprnt("(%s & %s)", 
                         expr_to_string(expr->x).c_str(), 
                         expr_to_string(expr->y).c_str());
            break;

        case cot_bor:  // Bitwise OR (|)
            result.sprnt("(%s | %s)", 
                         expr_to_string(expr->x).c_str(), 
                         expr_to_string(expr->y).c_str());
            break;
            
        case cot_sshr:
        case cot_ushr:
            result.sprnt("(%s >> %s)", 
                         expr_to_string(expr->x).c_str(), 
                         expr_to_string(expr->y).c_str());
            break;
            
        case cot_add:
            result.sprnt("(%s + %s)", 
                         expr_to_string(expr->x).c_str(), 
                         expr_to_string(expr->y).c_str());
            break;

        case cot_cast:  // Type cast
            {
                qstring type_str;
				expr->type.print(&type_str);
                // expr->type.get_nice_type_name(&type_str);
                result.sprnt("(%s)%s", type_str.c_str(), expr_to_string(expr->x).c_str());
            }
            break;
            
        case cot_call:  // Function call
            {
                qstring func_str = expr_to_string(expr->x); // Function address
                
                // Format arguments
                qstring args_str;
                carglist_t* args = expr->a;
                for (int i = 0; i < args->size(); i++) {
                    if (i > 0) args_str.append(", ");
                    args_str.append(expr_to_string(&(args->at(i))));
                }
                
                result.sprnt("%s(%s)", func_str.c_str(), args_str.c_str());
            }
            break;
        case cot_helper:  // Helper function (e.g., __builtin_*)
            result.sprnt("%s", expr->helper);
            break;

        default:
            result.sprnt("<%s:unknownop>", get_ctype_name(expr->op));
            break;
    }
    
    return result;
}

struct access_info
{
	cexpr_t* underlying_expr = nullptr;
	uint64_t mask;
	ea_t     ea;
	uint64_t byte_offset;
	uint8_t  shift_value;

	tinfo_t& type() const { return underlying_expr->type; }
	explicit operator bool() const { return underlying_expr != nullptr; }

	qstring to_string() const
	{
		qstring result;
		result.sprnt("access_info: expr=%s, mask=0x%llX, ea=0x%llX, byte_offset=%llu, shift_value=%u",
		             expr_to_string(underlying_expr).c_str(), mask, ea, byte_offset, shift_value);
		return result;
	}
};

// makes sure that the immediate / cot_num is on the right hand side
inline std::pair<cexpr_t*, cexpr_t*> normalize_binop( cexpr_t* expr )
{
	const auto num = expr->find_num_op();
	return { expr->theother( num ), num ? num : expr->y };
}

inline void replace_or_delete( cexpr_t* expr, cexpr_t* replacement, bool success )
{
	if ( !replacement )
		return;

	DLOG("  replace expr %s to %s, success=%d", expr_to_string(expr).c_str(), expr_to_string(replacement).c_str(), success);
	if ( success )
		expr->replace_by( replacement );
	else
		delete replacement;
}

inline void merge_accesses( cexpr_t*& original, cexpr_t* access, ctype_t op, ea_t ea, const tinfo_t& type )
{
	if ( !access )
		return;

	if ( !original )
		original = access;
	else
	{
		original = new cexpr_t( op, original, access );
		original->type = type;
		original->exflags = 0;
		original->ea = ea;
	}
}

// used for the allocation of helper names
inline char* alloc_cstr( const char* str )
{
	const auto len = strlen( str ) + 1;
	auto alloc = hexrays_alloc( len );
	if ( alloc )
		memcpy( alloc, str, len );
	return ( char* ) alloc;
}

// selects (adds memref expr) for the first member that is a struct inside of an union
inline void select_first_union_field( cexpr_t*& expr )
{
	if ( !expr->type.is_union() )
		return;

	udm_t member;
	for ( int i = 0; ; ++i )
	{
		member.offset = i;
		if ( expr->type.find_udm( &member, STRMEM_INDEX ) == -1 )
			break;

		if ( !member.type.is_struct() )
			continue;

		expr = new cexpr_t( cot_memref, expr );
		expr->type = member.type;
		expr->m = i;
		expr->exflags = 0;
		expr->ea = expr->x->ea;
		return;
	}
}

inline cexpr_t* create_bitfield_access( access_info& info, udm_t& member, ea_t original_ea, tinfo_t& common_type )
{
	func_type_data_t data;
	data.flags = FTI_PURE;
	data.rettype = member.size == 1 ? tinfo_t{ BTF_BOOL } : common_type;
	data.cc = CM_CC_UNKNOWN;

	{
		funcarg_t new_arg1;
		new_arg1.type = info.underlying_expr->type;
		funcarg_t new_arg2;
		new_arg2.type = common_type;
		data.push_back(new_arg1);
		data.push_back(new_arg2);
	// data.push_back( funcarg_t{ "", info.underlying_expr->type } );
	// data.push_back( funcarg_t{ "", common_type } );
	}

	tinfo_t functype;
	if ( !functype.create_func( data ) )
	{
		msg( "[bitfields] failed to create a bitfield access function type.\n" );
		return nullptr;
	}

	// construct the callable
	auto call_fn = new cexpr_t();
	call_fn->op = cot_helper;
	call_fn->type = functype;
	call_fn->exflags = 0;
	call_fn->helper = alloc_cstr( "b" );

	// construct the call args
	auto call_args = new carglist_t( std::move( functype ) );

	call_args->push_back( carg_t{} );
	auto& arg0 = ( *call_args )[ 0 ];
	static_cast< cexpr_t& >( arg0 ) = *info.underlying_expr;
	arg0.ea = info.ea;

	call_args->push_back( carg_t{} );
	auto& arg1 = ( *call_args )[ 1 ];
	arg1.op = cot_helper;
	arg1.type = common_type;
	arg1.exflags = EXFL_ALONE;
	arg1.helper = alloc_cstr( member.name.c_str() );

	// construct the call / access itself
	auto access = new cexpr_t( cot_call, call_fn );
	access->type = member.size == 1 ? tinfo_t{ BTF_BOOL } : common_type;
	access->exflags = 0;
	access->a = call_args;
	access->ea = original_ea;

	return access;
}

inline uint64_t bitfield_access_mask( udm_t& member )
{
	uint64_t mask = 0;
	for ( int i = member.offset; i < member.offset + member.size; ++i )
		mask |= ( 1ull << i );
	return mask;
}

// executes callback for each member in `type` where its offset coincides with `and_mask`.
// `cmp_mask` is used to calculate enabled bits in the bitfield.
template<class Callback>
bool for_each_bitfield( Callback cb, tinfo_t type, uint64_t and_mask, uint64_t byte_offset = 0 , uint8_t shift_value = 0 )
{
    qstring type_name;
    type.print(&type_name);
    DLOG("type=%s, and_mask=0x%X, byte_offset=%d, shift_value=%d", type_name.c_str(), and_mask, byte_offset, shift_value);

	udm_t member;

	if ( type.is_ptr() )
			type = type.get_ptrarr_object();

	for ( size_t i = 0; i < 64; ++i )
	{
		if ( !( and_mask & ( 1ull << (i + shift_value) ) ) )
			continue;

		const auto real_offset = (i + shift_value) + ( byte_offset * CHAR_BIT );
		member.offset = real_offset;
		if ( type.find_udm( &member, STRMEM_OFFSET ) == -1 )
			continue;

		if ( !member.is_bitfield() )
			continue;

		if ( member.offset != real_offset )
			continue;

        DLOG("  find member, type=%s, member=%s, member_size=%d, member_offset=%d, cur_offset=%d", type_name.c_str(),
            member.name.c_str(), member.size, member.offset, real_offset);

		uint64_t mask = bitfield_access_mask( member );
		if ( member.size != 1 && ( and_mask & mask ) != mask )
		{
			msg( "[bitfields] bad offset (%ull) and size (%ull) combo of a field for given mask (%ull)\n", member.offset, member.size, and_mask );
			return false;
		}

		cb( member );
	}
	return true;
}

// handles various cases of potential bitfield access.
// * (*(type*)&x >> imm1) & imm2
// * *(type*)&x & imm
// * HIDWORD(*(type*)&x)
// * *((DWORD*)expr + imm) & imm == imm
// * *((type*)ptr + offset) >> shift
inline access_info unwrap_access( cexpr_t* expr, bool is_assignee = false )
{
	access_info res{};

	if ( !is_assignee )
	{
		// handle simple bitfield access with binary and of a mask.
		// e.g. `x & 0x1`
		DLOG("    op=%s, expr=%s", get_ctype_name(expr->op), expr_to_string(expr).c_str());
		if ( expr->op == cot_band ) // Bitwise-AND
		{
			auto num = expr->find_num_op();
			if ( !num )
				return res;

			res.mask = num->n->_value;
			res.shift_value = 0;
			expr = expr->theother( num );
		}
		// handle special IDA macros that mask off words.
		// e.g. `LOBYTE(x)`
		else if ( expr->op == cot_call )
		{
			if ( expr->x->op != cot_helper || expr->a->size() != 1 )
				return res;

			constexpr static std::tuple<std::string_view, uint64_t, uint8_t> functions[] = {
				{"LOBYTE",  0x00'00'00'00'00'00'00'FF, 0 * 8},
				{"LOWORD",  0x00'00'00'00'00'00'FF'FF, 0 * 8},
				{"LODWORD", 0x00'00'00'00'FF'FF'FF'FF, 0 * 8},
				{"HIBYTE",  0xFF'00'00'00'00'00'00'00, 7 * 8},
				{"HIWORD",  0xFF'FF'00'00'00'00'00'00, 6 * 8},
				{"HIDWORD", 0xFF'FF'FF'FF'00'00'00'00, 4 * 8},
				{"BYTE1",   0x00'00'00'00'00'00'FF'00, 1 * 8},
				{"BYTE2",   0x00'00'00'00'00'FF'00'00, 2 * 8},
				{"BYTE3",   0x00'00'00'00'FF'00'00'00, 3 * 8},
				{"BYTE4",   0x00'00'00'FF'00'00'00'00, 4 * 8},
				{"BYTE5",   0x00'00'FF'00'00'00'00'00, 5 * 8},
				{"BYTE6",   0x00'FF'00'00'00'00'00'00, 6 * 8},
				{"WORD1",   0x00'00'00'00'FF'FF'00'00, 2 * 8},
				{"WORD2",   0x00'00'FF'FF'00'00'00'00, 4 * 8},
			};

			// check if it's one of the functions we care for
			auto it = std::ranges::find( functions, expr->x->helper, [ ] ( auto&& func ) { return std::get<0>( func ); } );
			if ( it == std::end( functions ) )
				return res;

			expr = &( *expr->a )[ 0 ];
			res.mask = std::get<1>( *it );
			res.shift_value = std::get<2>( *it );
		}
		// handle upper bit access that's transformed to a sign bit comparison.
		// e.g. `x < 0`
		else if ( expr->op == cot_slt )
		{
			auto num = expr->find_num_op();
			if ( !num || num->n->_value != 0 )
				return res;

			expr = expr->theother( num );
			res.mask = 1 << ( ( expr->type.get_size() * CHAR_BIT ) - 1 );
			res.shift_value = 0;
		}
		else if (expr->op == cot_ushr)
		{
			// handle right shift of a pointer dereference
			// e.g. `*((type *)var + 8) >> 6`
			auto shiftnum = expr->find_num_op();
			if ( !shiftnum )
				return res;

			expr = expr->theother( shiftnum );
			
			// Set mask based on the actual type size after dereference
			// For char*: mask = 0xFF, for short*: mask = 0xFFFF, etc.
			const auto type_size_bits = expr->type.get_size() * CHAR_BIT;
			res.mask = (1ull << type_size_bits) - 1;
			res.shift_value = ( uint8_t ) shiftnum->n->_value;
		}
		else
			return res;

		DLOG("  next expr=%s, mask=0x%llX, byte_offset=%u, shift_value=%u", expr_to_string(expr).c_str(),
			res.mask, res.byte_offset, res.shift_value);
		if ( expr->op == cot_ushr )
		{
			auto shiftnum = expr->find_num_op();
			if ( !shiftnum )
				return res;

			expr = expr->theother( shiftnum );
			if ( res.shift_value == 0 )
				res.mask <<= shiftnum->n->_value;

			res.shift_value += ( uint8_t ) shiftnum->n->_value;
		}
	}

	if ( expr->op != cot_ptr )
		return res;

	constexpr auto extract_topmost_ea_level2 = []( cexpr_t* expr ) -> ea_t {
		// extract the ea from one of the expression parts for union selection to work
		// thanks to @RolfRolles for help with making it work
		ea_t use_ea = expr->x->x->ea;
		use_ea = use_ea != BADADDR ? use_ea : expr->x->ea;
		use_ea = use_ea != BADADDR ? use_ea : expr->ea;
		if ( use_ea == BADADDR )
			msg( "[bitfields] can't find parent ea - won't be able to save union selection\n" );

		return use_ea;
	};

	if ( expr->x->op == cot_cast && expr->x->x->op == cot_ref )
	{
		DLOG("  handling cast+ref pattern: %s, %s", expr_to_string(expr).c_str(), expr_to_string(expr->x).c_str());
		res.underlying_expr = expr->x->x->x;
		res.ea = extract_topmost_ea_level2( expr );
	}
	else if ( expr->x->type.is_ptr() && ( expr->x->op == cot_add && expr->x->y->op == cot_num ) && expr->x->x->op == cot_cast )
	{
		DLOG("  handling cast+add pattern: %s, %s", expr_to_string(expr).c_str(), expr_to_string(expr->x).c_str());
		const auto* num = expr->x->y;
		res.byte_offset = expr->type.get_size() * num->n->_value;

		res.underlying_expr = expr->x->x->x;
		res.ea = extract_topmost_ea_level2( expr );
	}

	return res;
}

// e.g. if (((status & 0x2) >> 1) == 1) {}
inline void handle_equality( cexpr_t* expr )
{
	DLOG("origin expr: %s", expr_to_string(expr).c_str());
	auto [eq, eq_num] = normalize_binop( expr );
	if ( eq_num->op != cot_num )
		return;

	DLOG("  eq=%s, eq_num=%s", expr_to_string(eq).c_str(), expr_to_string(eq_num).c_str());
	auto info = unwrap_access( eq );
	if ( !info )
		return;

	cexpr_t* replacement = nullptr;
	auto success = for_each_bitfield(
		[ &, eq_num = eq_num ] ( udm_t& member )
		{
			// construct the call / access itself
			auto access = create_bitfield_access( info, member, expr->ea, eq_num->type );
			if ( !access )
				return;

			const auto mask = bitfield_access_mask( member );
			const auto value = ( ( eq_num->n->_value << info.shift_value ) & mask ) >> member.offset;

			// if the flag is multi byte, reconstruct the comparison
			if ( member.size > 1 )
			{
				auto num = new cnumber_t();
				num->assign( value, access->type.get_size(), member.type.is_signed() ? type_signed : type_unsigned );

				auto num_expr = new cexpr_t();
				num_expr->op = cot_num;
				num_expr->type = access->type;
				num_expr->n = num;
				num_expr->exflags = 0;

				access = new cexpr_t( expr->op, access, num_expr );
				access->type = tinfo_t{ BTF_BOOL };
				access->exflags = 0;
				access->ea = expr->ea;
			}
			// otherwise the flag is single bit; if the flag is disabled, add logical not
			else if ( value ^ ( expr->op == cot_eq ) )
			{
				access = new cexpr_t( cot_lnot, access );
				access->type = tinfo_t{ BTF_BOOL };
				access->exflags = 0;
				access->ea = expr->ea;
			}

			merge_accesses( replacement, access, expr->op == cot_eq ? cot_land : cot_lor, expr->ea, tinfo_t{ BTF_BOOL } );
		}, info.underlying_expr->type, info.mask, info.byte_offset );

	replace_or_delete( expr, replacement, success );
}

inline void handle_value_expr( cexpr_t* access )
{
	DLOG("origin expr: %s", expr_to_string(access).c_str());
	auto info = unwrap_access( access );
	if ( !info )
	{
		DLOG("  unwrap_access failed: %s", expr_to_string(access).c_str());
		return;
	}

	DLOG("  unwrap done, access info: %s", info.to_string().c_str());

	cexpr_t* replacement = nullptr;
	auto success = for_each_bitfield(
		[ & ] ( udm_t& member )
		{
			// TODO: for assignment where more than 1 field is being accessed create a new bitfield type for the result
			// that would contain the correctly masked and shifted fields
			const auto access = create_bitfield_access( info, member, info.ea, info.type() );
			merge_accesses( replacement, access, cot_bor, info.ea, info.type() );
		}, info.underlying_expr->type, info.mask, info.byte_offset , info.shift_value);

	replace_or_delete( access, replacement, success );
}

inline void handle_assignment( cexpr_t* expr )
{
	DLOG("");
	auto rhs = expr->y;
	auto info = unwrap_access( rhs );
	if ( !info )
		return;

	cexpr_t* replacement = nullptr;
	auto success = for_each_bitfield(
		[ & ] ( udm_t& member )
		{
			// TODO: for assignment where more than 1 field is being accessed create a new bitfield type for the result
			// that would contain the correctly masked and shifted fields
			const auto access = create_bitfield_access( info, member, expr->y->ea, expr->x->type );
			merge_accesses( replacement, access, cot_bor, rhs->ea, expr->x->type );
		}, info.underlying_expr->type, info.mask, info.byte_offset );

	replace_or_delete( expr->y, replacement, success );
}

// match |=
inline void handle_or_assignment( cexpr_t* expr )
{
	DLOG("");
	// second arg has to be a number
	auto& num = *expr->y;
	if ( num.op != cot_num )
		return;

	auto info = unwrap_access( expr->x, true );
	if ( !info )
		return;

	const auto mask = num.n->_value;
	cexpr_t* replacement = nullptr;
	const auto& type = info.type();
	bool success;
	if ( type.is_union() )
	{
		select_first_union_field( info.underlying_expr );
		success = for_each_bitfield(
			[ & ] ( udm_t& member )
			{
				auto helper = new cexpr_t();
				helper->op = cot_helper;
				helper->type = type;
				helper->ea = info.ea;
				helper->exflags = EXFL_ALONE;
				helper->helper = alloc_cstr( member.name.c_str() );

				merge_accesses( replacement, helper, cot_bor, info.ea, type );
			}, info.underlying_expr->type, mask, info.byte_offset );

		replace_or_delete( &num, replacement, success );
	}
	else
	{
		// this is a dirty hack to handle cases where we don't have a primitive union variable
		// to base the access off of. We'll have an internal error withut this.
		std::vector<char*> fields;
		success = for_each_bitfield(
			[ & ] ( udm_t& member )
			{
				fields.push_back( alloc_cstr( member.name.c_str() ) );
			}, info.underlying_expr->type, mask, info.byte_offset );

			if ( !success )
			{
				for ( auto& field : fields )
					delete field;

				return;
			}

			func_type_data_t data;
			data.flags = FTI_PURE;
			data.rettype = tinfo_t{ BTF_VOID };
			data.cc = CM_CC_UNKNOWN;
			data.reserve( fields.size() + 1 );
			for (size_t i = 0; i < fields.size() + 1; ++i)
			{
				funcarg_t arg;
				arg.type = info.underlying_expr->type;
				data.push_back(arg);
				//data.push_back(funcarg_t{ "", info.underlying_expr->type });
			}

			tinfo_t functype;
			if ( !functype.create_func( data ) )
			{
				msg( "[bitfields] failed to create a bitfield access function type.\n" );
				return;
			}

			// construct the callable
			auto call_fn = new cexpr_t();
			call_fn->op = cot_helper;
			call_fn->type = functype;
			call_fn->exflags = 0;
			call_fn->helper = alloc_cstr( "bset" );

			// construct the call args
			auto call_args = new carglist_t( std::move( functype ) );
			call_args->reserve(  data.size() );

			call_args->push_back( carg_t{} );
			auto& arg0 = ( *call_args )[ 0 ];
			static_cast< cexpr_t& >( arg0 ) = *info.underlying_expr;
			arg0.ea = info.ea;

			for (auto& field : fields)
			{
				call_args->push_back( carg_t{} );
				auto& arg1 = ( *call_args )[ 1 ];
				arg1.op = cot_helper;
				arg1.type = info.underlying_expr->type;
				arg1.exflags = EXFL_ALONE;
				arg1.helper = field;
			}

			// construct the call / access itself
			replacement = new cexpr_t( cot_call, call_fn );
			replacement->type = tinfo_t{ BTF_VOID };
			replacement->exflags = 0;
			replacement->a = call_args;
			replacement->ea = info.ea;

			replace_or_delete( expr, replacement, success );
	}

}

// match special bit functions
inline void handle_call( cexpr_t* expr )
{
	DLOG("");
	constexpr static size_t num_bitmask_funcs = 8;
	constexpr static std::string_view functions[] = {
		// bit mask functions
		"_InterlockedOr8",
		"_InterlockedOr16",
		"_InterlockedOr",
		"_InterlockedOr64",
		"_InterlockedAnd8",
		"_InterlockedAnd16",
		"_InterlockedAnd",
		"_InterlockedAnd64",
		// bit index functions
		"_bittest",
		"_bittest64",
		"_bittestandreset",
		"_bittestandreset64",
		"_bittestandset",
		"_bittestandset64",
		"_interlockedbittestandset",
		"_interlockedbittestandset64"
	};

	// we expect a helper whose name is one of special functions
	if ( expr->x->op != cot_helper )
		return;

	// 2 args
	if ( expr->a->size() != 2 )
		return;

	// (type*)& is expected for first arg
	cexpr_t* arg0 = &( *expr->a )[ 0 ];
	if ( arg0->op != cot_cast || arg0->x->op != cot_ref )
		return;

	// second arg has to be a number
	auto& arg1 = ( *expr->a )[ 1 ];
	if ( arg1.op != cot_num )
		return;

	// these functions will reference the union directly, so select a field for a start
	select_first_union_field( arg0->x->x );
	arg0 = arg0->x->x;

	// check if it's one of the functions we care for
	auto it = std::ranges::find( functions, expr->x->helper );
	if ( it == std::end( functions ) )
		return;

	auto mask = arg1.n->_value;

	// if it's a bitmask function make the mask 1 << n
	if ( std::distance( functions, it ) >= num_bitmask_funcs )
		mask = ( 1ull << mask );

	cexpr_t* replacement = nullptr;
	bool success = for_each_bitfield(
		[ & ] ( udm_t& member )
		{
			auto helper = new cexpr_t();
			helper->op = cot_helper;
			helper->type = arg1.type;
			helper->ea = arg1.ea;
			helper->exflags = EXFL_ALONE;
			helper->helper = alloc_cstr( member.name.c_str() );

			merge_accesses( replacement, helper, cot_bor, arg1.ea, arg1.type );
		}, arg0->type, mask );

	replace_or_delete( &arg1, replacement, success );
}

inline auto bitfields_optimizer = hex::hexrays_callback_for<hxe_maturity>(
	[ ] ( cfunc_t* cfunc, ctree_maturity_t maturity )->ssize_t
	{
		if ( maturity != CMAT_FINAL )
			return 0;
		msg("============================================================= bitfields start\n");

		struct visitor : ctree_visitor_t
		{
			visitor() : ctree_visitor_t( CV_FAST ) {}

			int idaapi visit_expr( cexpr_t* expr ) override
			{
				if ( expr->op == cot_eq || expr->op == cot_ne ) // equal or not-equal
					handle_equality( expr );
				// else if ( expr-> op == cot_slt ) // signed less than
					// handle_value_expr( expr );
				// else if ( expr->op == cot_call ) // call a function: foo(a, b)
				// 	handle_call( expr );
				else if ( expr->op == cot_asg ) // assign
					handle_value_expr( expr->y );
				// else if ( expr->op == cot_asgbor ) // assign with bitwise-OR: x |= y
				// 	handle_or_assignment( expr );

				return 0;
			}
		};

		visitor{}.apply_to( &cfunc->body, nullptr );

		msg("============================================================= bitfields end\n");
		return 0;
	} );

struct bitfields : plugmod_t
{
	netnode nn = { "$ bitfields", 0, true };

	void set_state( bool s )
	{
		msg("*****************************************************************\n");
		msg("      Plugin bitfields was %s: version 0.0.1 (%s)   \n", (s ? "enabled" : "disabled"), GIT_COMMIT_ID);
		msg("*****************************************************************\n\n");
		bitfields_optimizer.set_state( s );
	}

	// ctor
	bitfields()
	{
		set_state( nn.altval( 0 ) == 0 ); // enable when the altval is 0
	}

	~bitfields()
	{
		bitfields_optimizer.uninstall();
	}

	bool run( size_t ) override
	{
		constexpr const char* format = R"(
AUTOHIDE NONE
bitfields plugin for Hex-Rays decompiler (v0.0.1).
State: %s)";
		int code = ask_buttons( "~E~nable", "~D~isable", "~C~lose", -1, format + 1, nn.altval( 0 ) == 0 ? "Enabled" : "Disabled" );
		//  0: click enable button
		//  1: click disable button
		// -1: click close button or close dialog
		if ( code < 0 )
			return true;
		nn.altset( 0, code ? 0 : 1 );
		set_state( code );
		return true;
	}
};
plugin_t PLUGIN = { IDP_INTERFACE_VERSION, PLUGIN_MULTI, hex::init_hexray<bitfields>, nullptr, nullptr, "bitfields", nullptr, "bitfields", nullptr, };