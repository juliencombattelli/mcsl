#include <mcsl/string_view.h>

#include <gtest/gtest.h>

#include <cstring>

class string_view_base : public testing::Test {
protected:
    static inline const char c_str[] = "Hello world, hello everyone";
    mcsl_sv sv = mcsl_sv_make_from_c_str(c_str);
};

TEST_F(string_view_base, sv_make_from_c_str)
{
    ASSERT_EQ(sv.size, sizeof(c_str) - 1);
    ASSERT_TRUE(std::memcmp(sv.data, c_str, sv.size) == 0);
}

TEST_F(string_view_base, sv_data)
{
    ASSERT_EQ(mcsl_sv_data(sv), c_str);
}

TEST_F(string_view_base, sv_remove_prefix)
{
    mcsl_sv sv_without_prefix = mcsl_sv_remove_prefix(sv, 5);
    ASSERT_TRUE(std::memcmp(sv_without_prefix.data, &c_str[5], sv_without_prefix.size) == 0);
}

TEST_F(string_view_base, sv_remove_suffix)
{
    mcsl_sv sv_without_suffix = mcsl_sv_remove_suffix(sv, 5);
    ASSERT_TRUE(std::memcmp(sv_without_suffix.data, c_str, sv_without_suffix.size) == 0);
}

TEST_F(string_view_base, sv_ends_with__true)
{
    mcsl_sv one_suffix = mcsl_sv_make_from_c_str("one");
    bool ends_with_one = mcsl_sv_ends_with(sv, one_suffix);
    ASSERT_TRUE(ends_with_one);
}

TEST_F(string_view_base, sv_ends_with__false)
{
    mcsl_sv ome_suffix = mcsl_sv_make_from_c_str("ome");
    bool ends_with_ome = mcsl_sv_ends_with(sv, ome_suffix);
    ASSERT_FALSE(ends_with_ome);
}

TEST_F(string_view_base, sv_find__found)
{
    mcsl_sv wor = mcsl_sv_make_from_c_str("wor");
    size_t wor_index = mcsl_sv_find(sv, wor);
    ASSERT_EQ(wor_index, 6);
}

TEST_F(string_view_base, sv_find__not_found)
{
    mcsl_sv lde = mcsl_sv_make_from_c_str("lde");
    size_t lde_index = mcsl_sv_find(sv, lde);
    ASSERT_EQ(lde_index, mcsl_npos);
}

TEST_F(string_view_base, sv_rfind__found)
{
    mcsl_sv ello = mcsl_sv_make_from_c_str("ello");
    size_t ello_index = mcsl_sv_rfind(sv, ello);
    ASSERT_EQ(ello_index, 14);
}

TEST_F(string_view_base, sv_rfind__not_found)
{
    mcsl_sv lde = mcsl_sv_make_from_c_str("lde");
    size_t lde_index = mcsl_sv_rfind(sv, lde);
    ASSERT_EQ(lde_index, mcsl_npos);
}

TEST_F(string_view_base, sv_find_first_of__found)
{
    mcsl_sv def = mcsl_sv_make_from_c_str("def");
    size_t def_index = mcsl_sv_find_first_of(sv, def);
    ASSERT_EQ(def_index, 1);
}

TEST_F(string_view_base, sv_find_first_of__not_found)
{
    mcsl_sv abc = mcsl_sv_make_from_c_str("abc");
    size_t abc_index = mcsl_sv_find_first_of(sv, abc);
    ASSERT_EQ(abc_index, mcsl_npos);
}

TEST_F(string_view_base, sv_find_last_of__found)
{
    mcsl_sv def = mcsl_sv_make_from_c_str("def");
    size_t def_index = mcsl_sv_find_last_of(sv, def);
    ASSERT_EQ(def_index, 26);
}

TEST_F(string_view_base, sv_find_last_of__not_found)
{
    mcsl_sv abc = mcsl_sv_make_from_c_str("abc");
    size_t abc_index = mcsl_sv_find_last_of(sv, abc);
    ASSERT_EQ(abc_index, mcsl_npos);
}

TEST_F(string_view_base, sv_split__delim_space) {
    mcsl_sv tokens[8] = {0};
    mcsl_sv_split_result result = mcsl_sv_split(sv,
                                        mcsl_sv_make_from_c_str(" "),
                                        tokens, sizeof(tokens)/sizeof(tokens[0]));
    ASSERT_EQ(result.count, 4);
    ASSERT_EQ(result.stop, mcsl_sv_size(sv));
    ASSERT_TRUE(mcsl_sv_compare(tokens[0], mcsl_sv_make_from_c_str("Hello")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[1], mcsl_sv_make_from_c_str("world,")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[2], mcsl_sv_make_from_c_str("hello")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[3], mcsl_sv_make_from_c_str("everyone")) == 0);
}

TEST_F(string_view_base, sv_split__delim_space_o) {
    mcsl_sv tokens[8] = {0};
    mcsl_sv_split_result result = mcsl_sv_split(sv,
                                        mcsl_sv_make_from_c_str(" o"),
                                        tokens, sizeof(tokens)/sizeof(tokens[0]));
    ASSERT_EQ(result.count, 8);
    ASSERT_EQ(result.stop, mcsl_sv_size(sv));
    ASSERT_TRUE(mcsl_sv_compare(tokens[0], mcsl_sv_make_from_c_str("Hell")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[1], mcsl_sv_make_from_c_str("")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[2], mcsl_sv_make_from_c_str("w")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[3], mcsl_sv_make_from_c_str("rld,")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[4], mcsl_sv_make_from_c_str("hell")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[5], mcsl_sv_make_from_c_str("")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[6], mcsl_sv_make_from_c_str("every")) == 0);
    ASSERT_TRUE(mcsl_sv_compare(tokens[7], mcsl_sv_make_from_c_str("ne")) == 0);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}